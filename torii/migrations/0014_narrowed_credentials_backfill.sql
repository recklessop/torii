-- Mark already-scoped credentials NARROWED explicitly (#60).
--
-- The resolver used to infer "is this credential narrowed?" from whether it
-- currently carried any grant rows. That evaporates when an upstream is
-- disabled — `rbac._merge` drops the disabled upstream's rows, which could
-- empty the ceiling and flip a scoped key/connector back to its owner's FULL
-- baseline. Narrowing is now driven only by `access_mode`, so the mode is the
-- single source of truth.
--
-- The self-service scoping paths already set the mode. The admin grant editor
-- did not, so any credential scoped through it has grant rows but
-- `access_mode = 'inherit'`; under the stricter rule that would silently widen
-- it. Set those to 'narrowed' once. Idempotent, and a no-op on an instance
-- that never used the admin editor to scope a key or connector.

UPDATE oauth_clients c
   SET access_mode = 'narrowed', updated_at = now()
 WHERE c.access_mode = 'inherit'
   AND EXISTS (
       SELECT 1 FROM grants g
        WHERE g.subject_type = 'client' AND g.client_id = c.client_id
   );

UPDATE api_keys k
   SET access_mode = 'narrowed'
 WHERE k.access_mode = 'inherit'
   AND EXISTS (
       SELECT 1 FROM grants g
        WHERE g.subject_type = 'key' AND g.api_key_id = k.id
   );
