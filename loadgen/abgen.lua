-- modified version of Moongen example "l2-load-latency.lua"

local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"
local bit    = require "bit"
local dpdkc  = require "dpdkc"
local ffi    = require "ffi"
local abext  = require "proto.abext"
local pcap   = require "pcap"
local packet = require "packet"

local abgen = ffi.load("build/libabgen")
ffi.cdef[[
	void ab_generate_mac_ipv6_ext(int index, struct rte_mbuf *m, uint16_t payload_len,  uint8_t hdr_len);
	void ab_init_mac_ctx(int index, const uint8_t key[16]);
	int  ab_wrap_packet(int index, struct rte_mbuf *m,
	                    uint8_t idpid, uint16_t timeout,
	                    const uint8_t *eruid);
	void ab_gen_init(int index, const uint8_t *class_tbl, const uint8_t *sub_tbl,
	                 uint32_t alias_size, uint16_t src_base, uint32_t flow_limit);
	void ab_build_burst(int index, struct rte_mbuf **bufs, uint32_t n);
]]

-- Class tags (must match abgen.c).
local CLASS_LEGIT     = 1
local CLASS_NO_HEADER = 2
local CLASS_MALFORMED = 3
local CLASS_FORGED    = 4
local CLASS_REPLAY    = 5

-- Malformed sub-kinds (must match abgen.c).
local MAL_OPT_TYPE    = 0
local MAL_OPT_LEN     = 1
local MAL_TRUNCATED   = 2
local MAL_HDR_LEN     = 3
local MAL_MAC_GARBAGE = 4
local MAL_RANDOM      = 5

local MAL_KIND = {
	opt_type    = MAL_OPT_TYPE,
	opt_len     = MAL_OPT_LEN,
	truncated   = MAL_TRUNCATED,
	hdr_len     = MAL_HDR_LEN,
	mac_garbage = MAL_MAC_GARBAGE,
	random      = MAL_RANDOM,
}

local ALIAS_SIZE = 1024
local ALIAS_MASK = ALIAS_SIZE - 1

local function parseMix(s)
	local mix = {legit = 0, no_header = 0, malformed = 0, forged = 0, replay = 0}
	local seen = {}
	for pair in s:gmatch("[^,]+") do
		local k, v = pair:match("^%s*([%w_]+)%s*=%s*(%d+)%s*$")
		if not k then
			error(("cannot parse entry %q (expected key=pct)"):format(pair), 0)
		end
		if mix[k] == nil then
			error(("unknown class %q (expected one of legit, no_header, malformed, forged, replay)"):format(k), 0)
		end
		if seen[k] then
			error(("class %q specified more than once"):format(k), 0)
		end
		seen[k] = true
		mix[k] = tonumber(v)
	end
	local total = mix.legit + mix.no_header + mix.malformed + mix.forged + mix.replay
	if total ~= 100 then
		error(("percentages sum to %d, expected 100"):format(total), 0)
	end
	return mix
end

local function validateMalformedKind(s)
	if MAL_KIND[s] == nil then
		error("must be one of: opt_type, opt_len, truncated, hdr_len, mac_garbage, random", 0)
	end
	return s
end

function configure(parser)
	parser:description("Generate authenticated browsing packets (optionally mixed with attack traffic).")
	-- dev is optional now: an HTTP-only run (--http-in/--http-out without
	-- attack background) is a valid config, so accept zero positional args.
	parser:argument("dev", "Devices to transmit AB attack traffic from."):args("*"):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s. (0 to disable rate limiting)"):default(0):convert(tonumber)
    parser:option("-s --size", "Packet size in byte."):default(256):convert(tonumber)
    parser:option("-t --threads", "Number of Threads."):default(1):convert(tonumber)
	parser:option("-f --flows", "Number of Flows"):default(1):convert(tonumber)
	-- Validation runs in :convert so argparse catches bad input and prints
	-- a one-line usage message *before* DPDK initializes.
	parser:option("--mix",
		"Per-class traffic mix as comma-separated key=pct pairs. " ..
		"Keys: legit, no_header, malformed, forged, replay. Must sum to 100. " ..
		"Default is legit=100.")
		:default("legit=100")
		:convert(parseMix)
	parser:option("--malformed-kind",
		"Which malformation to emit when class=malformed. One of: " ..
		"opt_type, opt_len, truncated, hdr_len, mac_garbage, random. " ..
		"'random' distributes malformed slots evenly across all sub-kinds.")
		:default("random")
		:convert(validateMalformedKind)
	-- Wrap-forwarder ports. Both must be given together (or neither).
	-- http-in:  DPDK port where real HTTP traffic (from wrk2) arrives.
	-- http-out: DPDK port where wrapped packets are sent toward the validator
	--           (often the same as a --dev port so AB + HTTP share the link).
	-- Return path is a plain forwarder http-out rx -> http-in tx (no wrap).
	parser:option("--http-in",  "DPDK port for incoming wrk2 HTTP traffic."):convert(tonumber)
	parser:option("--http-out", "DPDK port for wrapped HTTP to validator."):convert(tonumber)
	parser:option("--http-out-mpps", "Cap http-out's AB rate (Mpps); keeps the shared HTTP wire under the validator NIC's limit."):convert(tonumber)
	-- Number of RX queues on http-out for the return-path plain forwarder
	-- (server replies). With one queue, brief NIC/PCIe stalls cause the
	-- single ring to overflow and drop the rare HTTP-reply packet sitting
	-- between bursts of attack traffic; the resulting packet loss triggers
	-- 200 ms TCP RTOs that wrk2 exposes as a fat p99.x tail. Splitting the
	-- return path across multiple RSS queues gives each ring more headroom
	-- and parallel descriptor refill.
	parser:option("--plain-fwd-queues", "RX queues for the return-path plain forwarder."):default(4):convert(tonumber)
end

getABPacket = createStack("eth", "ip6", "abext", "udp")

-- Build a pre-shuffled (class, sub_kind) slot table of size ALIAS_SIZE.
-- Hot loop walks the table with a counter & ALIAS_MASK (no RNG per packet).
local function buildAliasTable(mix, malformedKindName)
	local classTbl = ffi.new("uint8_t[?]", ALIAS_SIZE)
	local subTbl   = ffi.new("uint8_t[?]", ALIAS_SIZE)

	local function pctSlots(pct)
		return math.floor(pct * ALIAS_SIZE / 100 + 0.5)
	end

	local counts = {
		{cls = CLASS_LEGIT,     sub = 0, n = pctSlots(mix.legit)},
		{cls = CLASS_NO_HEADER, sub = 0, n = pctSlots(mix.no_header)},
		{cls = CLASS_MALFORMED, sub = MAL_KIND[malformedKindName] or MAL_RANDOM,
		                         n = pctSlots(mix.malformed)},
		{cls = CLASS_FORGED,    sub = 0, n = pctSlots(mix.forged)},
		{cls = CLASS_REPLAY,    sub = 0, n = pctSlots(mix.replay)},
	}

	-- Absorb rounding error into whichever non-zero class has the most slots.
	local sum = 0
	for _, c in ipairs(counts) do sum = sum + c.n end
	if sum ~= ALIAS_SIZE then
		local diff = ALIAS_SIZE - sum
		local best = 1
		for i, c in ipairs(counts) do
			if c.n > counts[best].n then best = i end
		end
		counts[best].n = counts[best].n + diff
	end

	-- Fill slots.
	local i = 0
	for _, c in ipairs(counts) do
		if c.cls == CLASS_MALFORMED and malformedKindName == "random" and c.n > 0 then
			-- Spread the malformed budget evenly across all sub-kinds.
			local subKinds = {MAL_OPT_TYPE, MAL_OPT_LEN, MAL_TRUNCATED, MAL_HDR_LEN, MAL_MAC_GARBAGE, MAL_RANDOM}
			local per = math.floor(c.n / #subKinds)
			local extra = c.n - per * #subKinds
			for k, sk in ipairs(subKinds) do
				local n = per + ((k <= extra) and 1 or 0)
				for _ = 1, n do
					classTbl[i] = c.cls
					subTbl[i]   = sk
					i = i + 1
				end
			end
		else
			for _ = 1, c.n do
				classTbl[i] = c.cls
				subTbl[i]   = c.sub
				i = i + 1
			end
		end
	end

	-- Fisher–Yates shuffle (classTbl[j] and subTbl[j] swap together).
	for j = ALIAS_SIZE - 1, 1, -1 do
		local r = math.random(0, j)
		classTbl[j], classTbl[r] = classTbl[r], classTbl[j]
		subTbl[j],   subTbl[r]   = subTbl[r],   subTbl[j]
	end

	return classTbl, subTbl
end

function master(args)
    dpdkc.rte_vect_set_max_simd_bitwidth(512)

	-- http-in and http-out must be specified together.
	if (args.http_in ~= nil) ~= (args.http_out ~= nil) then
		error("--http-in and --http-out must both be provided", 0)
	end
	if args.http_in and args.http_in == args.http_out then
		error("--http-in and --http-out must be different DPDK ports", 0)
	end
	local wrapMode = args.http_in ~= nil
	-- Either AB gen, HTTP wrap-fwd, or both.
	if (#args.dev == 0) and (not wrapMode) then
		error("nothing to do — pass at least one dev (AB gen) or --http-in/--http-out", 0)
	end

	-- Build per-port queue plan. A port can host several tasks:
	--   - args.threads gen tasks (tx only), for every port in args.dev
	--   - one wrapFwd tx queue, if port == http_out
	--   - one plainFwd tx queue, if port == http_in
	--   - one rx queue on http_in / http_out (for the two forwarders)
	-- Allocating tx queue indices contiguously below means gen tasks take
	-- queues 0..args.threads-1 and forwarders get args.threads (on shared
	-- ports) or 0 (on fresh ports).
	local plan = {}
	local function ensure(pid)
		if plan[pid] == nil then
			plan[pid] = {port = pid, rx = 0, tx = 0}
		end
		return plan[pid]
	end
	for _, pid in ipairs(args.dev) do
		local p = ensure(pid)
		p.genTxStart = p.tx
		p.tx = p.tx + args.threads
		p.isGenDev = true
	end
	if wrapMode then
		if args.plain_fwd_queues < 1 then
			error("--plain-fwd-queues must be >= 1", 0)
		end
		local pi = ensure(args.http_in)
		pi.rx = math.max(pi.rx, 1)
		-- TAP PMD in this DPDK build doesn't support multi-queue, so the plain
		-- forwarder uses a single shared TX queue into the TAP. Total return
		-- pps is small (only snorlax replies), so one TX queue isn't the
		-- bottleneck — the bottleneck was a single RX *ring* overflowing
		-- during NIC/PCIe stalls.
		pi.plainFwdTxIdx = pi.tx
		pi.tx = pi.tx + 1
		local po = ensure(args.http_out)
		-- N RX queues on http_out so RSS spreads snorlax-reply traffic across
		-- multiple rings (more total descriptor headroom; brief stalls hit one
		-- ring, not the only one). A single plainFwd task drains all of them.
		po.rx = math.max(po.rx, args.plain_fwd_queues)
		po.wrapFwdTxIdx = po.tx
		po.tx = po.tx + 1
	end
	-- Every port configured must still have an rx queue (MoonGen default
	-- is 1 rx queue even for tx-only generators — matches prior behaviour).
	for _, p in pairs(plan) do
		if p.rx == 0 then p.rx = 1 end
	end

	-- Configure each unique port once, in a deterministic order so the
	-- stats task prints ports in the same order every run.
	local portOrder = {}
	for pid, _ in pairs(plan) do portOrder[#portOrder + 1] = pid end
	table.sort(portOrder)

	-- Checksum offloads force i40e onto scalar TX (~half the pps), so only the TAP keeps them.
	local function isFwdPort(pid)
		return wrapMode and (pid == args.http_in or pid == args.http_out)
	end
	local configured = {}
	for _, pid in ipairs(portOrder) do
		local p = plan[pid]
		-- Enable RSS on http_out so multiple plainFwd RX queues actually get
		-- distributed traffic. Without rssQueues>0 MoonGen leaves RSS off and
		-- the NIC sends every packet to queue 0, defeating the parallelism.
		local rssQueues = 0
		if wrapMode and pid == args.http_out and p.rx > 1 then
			rssQueues = p.rx
		end
		configured[pid] = device.config({
			port = pid, rxQueues = p.rx, txQueues = p.tx,
			rssQueues = rssQueues,
			disableOffloads = not (wrapMode and pid == args.http_in),
		})
		-- Forwarder ports must accept packets whose dst MAC was rewritten
		-- by the validator's bridge mode (typically the ctx->dst_mac from
		-- mac.conf, not the NIC's own MAC). Without promisc, the NIC
		-- would drop these.
		if isFwdPort(pid) then
			configured[pid]:setPromisc(true)
		end
	end

	device.waitForLinks()

	-- remove size of automatically added crc
	args.size = args.size - 4

	-- Rate limiter applies only to AB generator devices. HTTP forwarders
	-- run unlimited; their rate is bounded by wrk2's offered load.
	if args.rate ~= 0 then
		for _, pid in ipairs(args.dev) do
			local rate = args.rate / #args.dev
			if pid == args.http_out and args.http_out_mpps then
				rate = math.min(rate, args.http_out_mpps * args.size * 8)
			end
			configured[pid]:setRate(rate)
		end
	end

	-- Read the pcap template once here and pass the bytes to each gen task
	-- as a Lua string. Previously every thread created its own default-sized
	-- mempool just to read this one packet, which at -t 16 across 4 NICs
	-- (64 threads × 2 mempools) exhausts hugepage memory and DPDK fails the
	-- tx-pool allocation with -ENOMEM, then segfaults on the NULL pool.
	-- n=511 is the smallest 2^k-1 that clears DPDK's cache_size*1.5 minimum
	-- (MoonGen hardcodes cache=256, so n must be >= 384). We only need it to
	-- read one packet, so we don't pay the default 2047-buf cost.
	local templateMempool = memory.createMemPool{n = 511}
	local pcapReader = pcap:newReader("/root/AuthBrowsing-dpdk/loadgen/inbound.pcap")
	local templatePkt = pcapReader:readSingle(templateMempool)
	local templateSize = templatePkt:getSize()
	local templateBytes = ffi.string(templatePkt:getRawPacket().payload, templateSize)
	pcapReader:close()

	-- Stats prints every port we configured, so the HTTP-forwarder ports
	-- show up alongside the generator ports.
	local statsDevs = {}
	for _, pid in ipairs(portOrder) do statsDevs[#statsDevs + 1] = configured[pid] end
	stats.startStatsTask(statsDevs)

	-- Generator tasks, one per (dev, thread) pair, keyed on a global ctx
	-- index that must match the C-side ab_init_mac_ctx index.
	local genCtxCount = 0
	for j, pid in ipairs(args.dev) do
		local dev = configured[pid]
		for i = 1, args.threads do
			local ctxIdx = (j - 1) * args.threads + (i - 1)
			mg.startTask("gen", dev:getTxQueue(plan[pid].genTxStart + (i - 1)), ctxIdx, args, templateBytes, templateSize)
			genCtxCount = genCtxCount + 1
		end
	end

	-- HTTP wrap forwarder: receives real IPv6/TCP from wrk2, prepends the
	-- AB extension header, signs, and forwards toward the validator. A
	-- separate plain forwarder carries the return path (validator -> wrk2)
	-- unchanged so the server's replies reach the client unmodified.
	if wrapMode then
		local wrapCtxIdx = genCtxCount   -- first ctx index after gen tasks
		mg.startTask("wrapFwd",
			configured[args.http_in]:getRxQueue(0),
			configured[args.http_out]:getTxQueue(plan[args.http_out].wrapFwdTxIdx),
			wrapCtxIdx)
		-- Single plainFwd task draining N RX queues round-robin. RSS spreads
		-- inbound replies across the queues; the task's per-iteration loop
		-- visits each queue, so no ring sits long enough to overflow during a
		-- PCIe stall. Pass http_out's port id + queue count and let the task
		-- reconstruct the rxQueue handles in its own Lua state (MoonGen
		-- serialises args across task boundaries).
		mg.startTask("plainFwdMulti",
			args.http_out,
			args.plain_fwd_queues,
			configured[args.http_in]:getTxQueue(plan[args.http_in].plainFwdTxIdx))
	end

	mg.waitForTasks()
end

function gen(queue, index, args, templateBytes, templateSize)
	local mac_key = ffi.new("uint8_t[16]")
	for k = 0, 15 do mac_key[k] = 0 end

	abgen.ab_init_mac_ctx(index, mac_key)

	local udpPayloadLen = args.size - 86 -- subtract headers: eth 14, ip6 40, abext 24, udp 8
    local udpPayload = ffi.new("uint8_t[?]", udpPayloadLen)
    for i = 0, udpPayloadLen - 1 do
        udpPayload[i] = bit.band(i, 0xf)
    end

	-- IPv6 Extension Header
	local mem = memory.createMemPool(function(buf)
		ffi.copy(buf:getRawPacket().payload, templateBytes, templateSize)
		local pkt = getABPacket(buf)
		pkt.eth:setSrcString("3c:fd:fe:9e:8e:39")
		pkt.eth:setDstString("3c:fd:fe:9e:97:31")
		pkt.ip6:setSrcString("2001:db8::1")
		pkt.ip6:setDstString("2001:db8::2")
		pkt.udp:setSrcPort(8000)
		pkt.udp:setDstPort(443)
        pkt:setLength(args.size)
        -- fill udp payload with prepared udp payload
        ffi.copy(pkt.payload, udpPayload, udpPayloadLen)
	end)

	local flowLimit = math.floor(args.flows / #args.dev / args.threads)
	if flowLimit < 1 then flowLimit = 1 end
	local srcBase = 8000 + math.floor(args.flows / #args.dev / args.threads) * index

	-- Mix: per-thread alias table (same ratios as --mix but shuffled
	-- independently so adjacent threads don't emit identical class patterns).
	-- The per-packet work (class, sequence numbers, eruid/timeout, flow
	-- rotation) runs in C, one ab_build_burst call per burst, so this loop has
	-- no class-dependent branches. Branching on the class here pushed LuaJIT
	-- off its compiled trace whenever classes were mixed, which made the
	-- offered rate depend on the mix (at -s 92: ~155 Mpps at 1% and 99%
	-- forged, ~133 Mpps at 20-50%).
	math.randomseed(index + 1)
	local classTbl, subTbl = buildAliasTable(args.mix, args.malformed_kind)
	abgen.ab_gen_init(index, classTbl, subTbl, ALIAS_SIZE, srcBase, flowLimit)

	local bufs = mem:bufArray(128)
	while mg.running() do
		bufs:alloc(args.size)
		abgen.ab_build_burst(index, bufs.array, bufs.size)
		queue:send(bufs)
	end
end

-- Wrap-and-forward: receive real IPv6/TCP packets on rxQueue, prepend the
-- AB destination-options ext header with a valid PMAC tag, and forward on
-- txQueue. Non-IPv6/non-TCP frames (NDP, ARP, UDP) pass through untouched
-- so the client/server's L2/L3 resolution still works.
--
-- `index` is the abgen MAC context slot used for this task — must be unique
-- across all tasks that call any ab_* MAC-producing function, and chosen to
-- not collide with the gen tasks' context indices.
-- Build-up plan (set RAW_FWD=1 to skip the wrap and just forward raw,
-- so we can isolate TAP↔DPDK↔wire↔DPDK↔TAP plumbing before adding the AB
-- ext header on top).
local RAW_FWD = os.getenv("RAW_FWD") == "1"

function wrapFwd(rxQueue, txQueue, index)
	local mac_key = ffi.new("uint8_t[16]")
	for k = 0, 15 do mac_key[k] = 0 end
	abgen.ab_init_mac_ctx(index, mac_key)

	local TEMPLATE_IDPID   = 0x11
	local TEMPLATE_TIMEOUT = 1
	local ERUID_PREFIX     = {0xde, 0xad}

	local eruidBuf    = ffi.new("uint8_t[7]")
	local seqScratch  = ffi.new("uint64_t[1]")
	local seqScratchP = ffi.cast("uint8_t *", seqScratch)
	seqScratch[0]     = 0ULL
	eruidBuf[0] = ERUID_PREFIX[1]
	eruidBuf[1] = ERUID_PREFIX[2]
	eruidBuf[2] = index + 1

	local bufs = memory.bufArray()
	while mg.running() do
		local rx = rxQueue:tryRecv(bufs, 100)
		if rx > 0 then
			if not RAW_FWD then
				for i = 1, rx do
					bufs[i].ol_flags = 0
					eruidBuf[3] = seqScratchP[0]
					eruidBuf[4] = seqScratchP[1]
					eruidBuf[5] = seqScratchP[2]
					eruidBuf[6] = seqScratchP[3]
					seqScratch[0] = seqScratch[0] + 1ULL
					abgen.ab_wrap_packet(index, bufs[i],
						TEMPLATE_IDPID, TEMPLATE_TIMEOUT, eruidBuf)
				end
			else
				for i = 1, rx do bufs[i].ol_flags = 0 end
			end
			txQueue:sendN(bufs, rx)
		end
	end
end

-- Plain forward (no modification): used for the server -> client return path
-- where the validator has already stripped the AB ext header (or left it in
-- place for the client to ignore). The server's TCP replies reach wrk2 as-is.
function plainFwd(rxQueue, txQueue)
	local bufs = memory.bufArray()
	while mg.running() do
		local rx = rxQueue:recv(bufs)
		txQueue:sendN(bufs, rx)
	end
end

-- Multi-queue plainFwd: poll N RX queues on http_out round-robin and tx into
-- a single TAP TX queue. The round-robin keeps every ring drained; combined
-- with RSS distributing snorlax replies across the rings, brief NIC/PCIe
-- stalls hit one ring at a time and never overflow it. Single TX is fine
-- because total reply pps is small (TAP PMD here doesn't support multi-queue
-- anyway).
function plainFwdMulti(httpOutPid, queueCount, txQueue)
	local dev = require("device")
	local rxQueues = {}
	for q = 0, queueCount - 1 do
		rxQueues[q + 1] = dev.get(httpOutPid):getRxQueue(q)
	end
	local bufs = memory.bufArray()
	while mg.running() do
		for i = 1, queueCount do
			local rx = rxQueues[i]:tryRecv(bufs, 0)
			if rx > 0 then
				txQueue:sendN(bufs, rx)
			end
		end
	end
end
