-- Corrección para permitir intercambios de cromos con cantidad = 1 (útil para Diamantes, Esmeraldas, etc.)
-- Al bajar la cantidad a 0, el cromo desaparecerá visualmente del inventario y el usuario podrá pedirlo nuevamente.

CREATE OR REPLACE FUNCTION album.execute_trade(
    p_requester_ids text[],
    p_accepter_ids text[],
    p_requester_increment_id text,
    p_accepter_increment_id text,
    p_offer_ids text[],
    p_want_ids text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_item text;
    v_updated_id uuid;
BEGIN
    -- 1. Restar offer_ids del requester
    FOREACH v_item IN ARRAY p_offer_ids LOOP
        v_updated_id := NULL;
        WITH cte AS (
            SELECT id, quantity
            FROM album.user_stickers
            WHERE user_id = ANY(p_requester_ids) AND sticker_id = v_item::uuid
            ORDER BY quantity DESC, id ASC
            LIMIT 1
        )
        UPDATE album.user_stickers us
        SET quantity = us.quantity - 1
        FROM cte
        WHERE us.id = cte.id AND cte.quantity > 0
        RETURNING us.id INTO v_updated_id;

        IF v_updated_id IS NULL THEN
            RAISE EXCEPTION 'album_trade_requester_inventory_changed:%', v_item;
        END IF;
    END LOOP;

    -- 2. Restar want_ids del accepter
    FOREACH v_item IN ARRAY p_want_ids LOOP
        v_updated_id := NULL;
        WITH cte AS (
            SELECT id, quantity
            FROM album.user_stickers
            WHERE user_id = ANY(p_accepter_ids) AND sticker_id = v_item::uuid
            ORDER BY quantity DESC, id ASC
            LIMIT 1
        )
        UPDATE album.user_stickers us
        SET quantity = us.quantity - 1
        FROM cte
        WHERE us.id = cte.id AND cte.quantity > 0
        RETURNING us.id INTO v_updated_id;

        IF v_updated_id IS NULL THEN
            RAISE EXCEPTION 'album_trade_counter_inventory_missing:%', v_item;
        END IF;
    END LOOP;

    -- 3. Sumar offer_ids al accepter
    FOREACH v_item IN ARRAY p_offer_ids LOOP
        INSERT INTO album.user_stickers (user_id, sticker_id, quantity)
        VALUES (p_accepter_increment_id, v_item::uuid, 1)
        ON CONFLICT (user_id, sticker_id) DO UPDATE
        SET quantity = album.user_stickers.quantity + 1;
    END LOOP;

    -- 4. Sumar want_ids al requester
    FOREACH v_item IN ARRAY p_want_ids LOOP
        INSERT INTO album.user_stickers (user_id, sticker_id, quantity)
        VALUES (p_requester_increment_id, v_item::uuid, 1)
        ON CONFLICT (user_id, sticker_id) DO UPDATE
        SET quantity = album.user_stickers.quantity + 1;
    END LOOP;
END;
$$;
