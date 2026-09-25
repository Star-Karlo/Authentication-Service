UPDATE roles
SET permissions = array_remove(array_remove(permissions, 'tms:warehouse.read'), 'tms:dispatch.read'),
    updated_at = now()
WHERE name = 'Driver' AND is_system;
