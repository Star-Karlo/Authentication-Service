-- A short code for each company, used to build agreement numbers.
--
-- The PRD and the reference UI both number agreements AGR-JYA-ASB-000001:
-- the transporter's code, the client's code, then a sequence. Ours produced
-- AGR-2026-000001, which is unique and says nothing — a number nobody can read
-- back to a counterparty over the phone, which is most of what an agreement
-- number is for.
--
-- Three letters because that is what the format has room for, and because the
-- people using it are reading it aloud.

BEGIN;

ALTER TABLE companies
    ADD COLUMN abbreviation VARCHAR(8);

-- Derived from the name for every company that already exists.
--
-- The rule: drop the legal-form words that begin nearly every Indonesian
-- company name — PT, CV, UD, PD and the Tbk suffix — because "PT Sumber Makmur"
-- and "PT Sinar Jaya" would otherwise both abbreviate to PTS. Then take the
-- initial of each remaining word.
--
-- Deliberately NOT unique. Two companies can genuinely share three letters, and
-- refusing the second one would block a registration for a cosmetic reason; the
-- agreement number is unique through its sequence, not through the codes. What
-- the code buys is legibility, and a duplicate costs only that.
WITH derived AS (
    SELECT
        c.id,
        UPPER(LEFT(
            COALESCE(
                (
                    SELECT string_agg(LEFT(word, 1), '' ORDER BY ordinality)
                    FROM unnest(string_to_array(
                        regexp_replace(
                            -- Strip punctuation first, so "PT. Sumber" and
                            -- "PT Sumber" derive the same code.
                            regexp_replace(c.name, '[^a-zA-Z0-9 ]', ' ', 'g'),
                            '(^|\s)(PT|CV|UD|PD|Tbk)(\s|$)', ' ', 'gi'
                        ),
                        ' '
                    )) WITH ORDINALITY AS t(word, ordinality)
                    WHERE word <> ''
                ),
                ''
            ),
        3)) AS code
    FROM companies c
)
UPDATE companies c
SET abbreviation = NULLIF(d.code, '')
FROM derived d
WHERE c.id = d.id;

-- A one-word name yields one initial, which is not a code anybody can read
-- back — "MAST" would become "M". Anything shorter than two characters falls
-- back to the first three letters of the name instead: MAST becomes MAS.
--
-- Two is the threshold rather than three because a genuine two-initial code
-- ("Karlo Platform" -> KP) is perfectly readable, while a single letter is not.
UPDATE companies
SET abbreviation = UPPER(LEFT(regexp_replace(name, '[^a-zA-Z0-9]', '', 'g'), 3))
WHERE (abbreviation IS NULL OR length(abbreviation) < 2)
  AND regexp_replace(name, '[^a-zA-Z0-9]', '', 'g') <> '';

UPDATE companies SET abbreviation = 'CO' WHERE abbreviation IS NULL;

-- Supports "who else uses this code", which an administrator wants before
-- choosing a replacement.
CREATE INDEX idx_companies_abbreviation ON companies (abbreviation)
    WHERE deleted_at IS NULL;

COMMENT ON COLUMN companies.abbreviation IS
    'Short code used in agreement numbers (AGR-<transporter>-<client>-000001). Derived from the name on creation and editable. NOT unique: uniqueness comes from the sequence, and refusing a duplicate would block a registration for a cosmetic reason.';

COMMIT;
