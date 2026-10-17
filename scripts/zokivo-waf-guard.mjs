import {createHash} from 'node:crypto';

export const HOST = 'zokivo.vynalthai.com';
const SAFE_EXPRESSIONS = new Set([
  '(http.host eq "zokivo.vynalthai.com" and starts_with(http.request.uri.path, "/api/rooms/"))',
  '(http.host eq "zokivo.vynalthai.com" and http.request.uri.path starts_with "/api/rooms/")',
  '(http.host eq "zokivo.vynalthai.com" and http.request.uri.path matches "^/api/rooms/")',
]);

export function fingerprint(rule) {
  const selected = {
    id:rule.id,version:rule.version,action:rule.action,expression:rule.expression,
    enabled:rule.enabled,description:rule.description,
    ratelimit:rule.ratelimit,action_parameters:rule.action_parameters,
  };
  return createHash('sha256').update(JSON.stringify(selected)).digest('hex');
}

export function proposeNatCounter(rule) {
  if (!rule || typeof rule !== 'object') throw new Error('RULE_NOT_FOUND');
  if (rule.enabled === false) throw new Error('RULE_DISABLED');
  if (rule.action !== 'block') throw new Error('ONLY_BLOCK_RATE_RULES_SUPPORTED');
  if (!SAFE_EXPRESSIONS.has((rule.expression || '').trim()))
    throw new Error('RULE_NOT_EXCLUSIVELY_SCOPED_TO_ZOKIVO_GAME_API: inspect and split shared/complex rules manually');
  const rate = rule.ratelimit;
  if (!rate || typeof rate !== 'object') throw new Error('MISSING_RATE_LIMIT_OBJECT');
  if (!Number.isSafeInteger(rate.requests_per_period) || rate.requests_per_period < 1 ||
      !Number.isSafeInteger(rate.period) || rate.period < 1)
    throw new Error('INVALID_RATE_LIMIT_SETTINGS');
  if (typeof rate.counting_expression === 'string' && /\bip\.src\b/.test(rate.counting_expression))
    throw new Error('COUNTING_EXPRESSION_HAS_SOURCE_IP');
  if (!Array.isArray(rate.characteristics) ||
      !rate.characteristics.includes('ip.src') ||
      !rate.characteristics.includes('cf.colo.id') ||
      rate.characteristics.includes('cf.unique_visitor_id'))
    throw new Error('EXPECTED_IP_BASED_COUNTER_NOT_FOUND');
  if (rate.characteristics.some(x => /http\.request\.(headers|cookies)\[/.test(x)))
    throw new Error('CUSTOM_COUNTER_CHARACTERISTIC_REQUIRES_MANUAL_REVIEW');
  const characteristics = rate.characteristics.map(x => x==='ip.src' ? 'cf.unique_visitor_id' : x);
  const patch = {
    action:rule.action,expression:rule.expression,description:rule.description || '',
    enabled:rule.enabled !== false,ratelimit:{...rate,characteristics},
    ...(rule.action_parameters ? {action_parameters:rule.action_parameters} : {}),
    ...(rule.ref ? {ref:rule.ref} : {}),
    ...(rule.logging ? {logging:rule.logging} : {}),
  };
  return {
    patch,before:fingerprint(rule),
    publicSummary:{
      hostname:HOST,ruleIdSuffix:String(rule.id).slice(-8),action:rule.action,
      periodSeconds:rate.period,requestsPerPeriod:rate.requests_per_period,
      beforeCharacteristics:[...rate.characteristics],
      afterCharacteristics:[...characteristics],
      note:'No changes to rate thresholds, mitigation timeout, expression, or action',
    },
  };
}
