-- csm-managed-version: 1
-- CSM antispam scope and scan record. Installed and removed by CSM; local
-- edits are lost. CSM enforces only on unauthenticated mail from remote
-- hosts. Mail whose every recipient is exempt is scored and logged, never
-- enforced. In dry run the host's own actions keep deciding.

local rspamd_logger = require 'rspamd_logger'

local MODE = $MODE
local REJECT, TAG = $REJECT, $TAG
local NETS = { $NETS }
local EXEMPT = { $EXEMPT }

local nets
if #NETS > 0 then
  nets = rspamd_config:radix_from_ucl(NETS, 'CSM infra_ips')
end
local mailboxes, domains = {}, {}
for _, e in ipairs(EXEMPT) do
  if e:find('@', 1, true) then
    mailboxes[e] = true
  else
    domains[e] = true
  end
end

-- scope returns 'out' for mail CSM never scores (authenticated, local or
-- from infra_ips), 'off' when every SMTP recipient is exempt and 'on'
-- otherwise. strip is true for the mail milter_headers skips, which would
-- keep an inbound X-Spam-Status.
local function scope(task)
  if task:get_user() then
    return 'out', true
  end
  local ip = task:get_from_ip()
  if ip and ip:is_valid() then
    if ip:is_local() then
      return 'out', true
    end
    if nets and nets:get_key(ip) then
      return 'out', false
    end
  end
  local rcpts = task:get_recipients('smtp')
  if not rcpts or #rcpts == 0 then
    return 'on', false
  end
  -- One exempt recipient must not exempt the others.
  for _, r in ipairs(rcpts) do
    local addr = string.lower(r.addr or '')
    if not mailboxes[addr] and not domains[addr:match('@([^@]*)$') or ''] then
      return 'on', false
    end
  end
  return 'off', false
end

rspamd_config:register_symbol({
  name = 'CSM_SCOPE',
  type = 'prefilter',
  priority = 10,
  callback = function(task)
    local policy, strip = scope(task)
    if strip then
      task:set_milter_reply({ remove_headers = { ['X-Spam-Status'] = 0 } })
    end
    if MODE == 'enforce' and policy ~= 'on' then
      task:set_settings({ actions = { reject = 100000, ['add header'] = 100000,
        ['rewrite subject'] = 100000, greylist = 100000 } })
    end
  end,
})

-- One record per scored message. The score is in tenths, rounded down, so
-- it meets a threshold exactly when rspamd's score does.
rspamd_config:register_symbol({
  name = 'CSM_MARKER',
  type = 'idempotent',
  callback = function(task)
    local policy = scope(task)
    if policy == 'out' then
      return
    end
    local res = task:get_metric_result()
    local score = math.floor(res.score * 10)
    local decision = 'unfiltered'
    if policy == 'on' then
      decision = score >= REJECT and 'reject' or score >= TAG and 'tag' or 'none'
    end
    local ip = task:get_from_ip()
    rspamd_logger.infox(task, '%s', string.format(
      'CSM-ANTISPAM event=scan mode=%s policy=%s result=ok score=%d action="%s" decision=%s ip=%s qid=%s',
      MODE, policy, score, (res.action:gsub('[^a-z ]', '_')), decision,
      ip and ip:is_valid() and ip:to_string() or '',
      ((task:get_queue_id() or ''):gsub('[^0-9A-Za-z]', '_'))))
  end,
})
