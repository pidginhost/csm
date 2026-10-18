-- csm-managed-version: 1
-- CSM learning inspection. Installed and removed by CSM; local edits are lost.
-- POST /plugins/csm_learning/inspect with the message as the body. The only
-- parameter is digests: a comma-separated list of full digests for exact
-- checks. Caller-selected rules, servers or paths are not accepted.

local RULE = 'csm'
local MAX_DIGESTS = 64
local CHECK_TIMEOUT = 2.0
local REPLY_TIMEOUT = 3.0

local function valid_digest(h)
  return #h == 128 and h:match('^[0-9a-f]+$') ~= nil
end

-- parse_digests returns the distinct digests and their count, or nil and an
-- error for an empty, malformed or oversized list.
local function parse_digests(param)
  local list, seen, n = {}, {}, 0
  for h in (param .. ','):gmatch('([^,]*),') do
    if not valid_digest(h) then
      return nil, 'invalid digest'
    end
    if not seen[h] then
      seen[h] = 1
      n = n + 1
      if n > MAX_DIGESTS then
        return nil, 'too many digests'
      end
      list[n] = h
    end
  end
  return list, seen, n
end

local function same_reply(a, b)
  return a.found == b.found and a.digest == b.digest and a.prob == b.prob and
    a.value == b.value and a.flag == b.flag and a.confirmed == b.confirmed
end

local function inspect(task, conn, req_params)
  local fc = rspamd_plugins.fuzzy_check
  local explicit, expected, distinct
  if req_params.digests ~= nil then
    local list, seen, n = parse_digests(req_params.digests)
    if not list then
      conn:send_error(400, seen)
      return
    end
    explicit, expected, distinct = list, seen, n
  end

  local results, errors, replied = {}, {}, false
  local by_digest, received = {}, {}
  local function reply()
    if replied then return end
    replied = true
    local complete = #errors == 0 and #results == distinct
    conn:send_ucl({ results = results, errors = errors, complete = complete, distinct = distinct })
  end
  local function fail(msg)
    errors[#errors + 1] = msg
    reply()
  end

  task:process_message()
  if not explicit then
    local ok, hashes = pcall(fc.hex_hashes, task, 1)
    if not ok or type(hashes) ~= 'table' then
      distinct = 0
      fail('cannot hash message')
      return
    end
    expected, distinct = {}, 0
    for _, h in ipairs(hashes[RULE] or {}) do
      if expected[h] == nil then
        distinct = distinct + 1
        expected[h] = 0
      end
      -- Identical MIME parts are queried once each; their replies must agree.
      expected[h] = expected[h] + 1
    end
    if distinct > MAX_DIGESTS then
      fail('too many digests')
      return
    end
  end
  if distinct == 0 then
    reply()
    return
  end

  local function on_reply(success, _addr, res)
    if replied then return end
    if not success then
      fail(tostring(res))
      return
    end
    if type(res) ~= 'table' or type(res.queried) ~= 'string' or expected[res.queried] == nil then
      fail('unexpected reply')
      return
    end
    local q = res.queried
    received[q] = (received[q] or 0) + 1
    if received[q] > expected[q] then
      fail('duplicate reply')
      return
    end
    local r = { queried = q, found = res.found == true, digest = res.digest, prob = res.prob,
      value = res.value, flag = res.flag, confirmed = res.confirmed == true }
    if by_digest[q] then
      if not same_reply(by_digest[q], r) then
        fail('inconsistent replies')
      end
      return
    end
    by_digest[q] = r
    results[#results + 1] = r
    if #results == distinct then
      reply()
    end
  end

  task:add_timer(REPLY_TIMEOUT, function()
    if not replied then fail('timeout') end
  end)
  local pok, cok, cerr = pcall(fc.check, task, on_reply, RULE, CHECK_TIMEOUT, explicit)
  if not pok then
    fail(tostring(cok))
  elseif not cok then
    fail(tostring(cerr or 'check refused'))
  end
end

rspamd_plugins.csm_learning = {
  webui = {
    inspect = { handler = inspect, need_task = true, enable = true },
  },
}
