-- Tabla para registrar resultados del Bracket (quien gano cada pelea oficial)
CREATE TABLE IF NOT EXISTS bracket_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  division text NOT NULL, -- 'ciudad' o 'universal'
  match_code text NOT NULL, -- 'CL1', 'CR1', 'U1', etc.
  winner_pseudo text NOT NULL,
  loser_pseudo text NOT NULL,
  round int NOT NULL, -- 1=octavos/grupos, 2=cuartos/semis, 3=semis/final de 3
  created_at timestamptz DEFAULT now()
);

-- Para búsquedas rápidas en resultados del bracket
CREATE INDEX IF NOT EXISTS idx_bracket_results_division_match ON bracket_results(division, match_code);

-- Tabla para crear peleas abiertas a apuestas
CREATE TABLE IF NOT EXISTS bet_fights (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  fight_id text NOT NULL UNIQUE, -- Identificador único de la pelea, ej: 'apuesta-ciudad-cl1'
  division text NOT NULL,
  label text NOT NULL, -- Ej: 'Ciudad: Octavos - Khamzat vs Amiya'
  fighter_a text NOT NULL,
  fighter_b text NOT NULL,
  status text DEFAULT 'open', -- 'open' (apuestas permitidas), 'closed' (no se recibiran más), 'resolved' (pagadas)
  winner_pseudo text,
  created_at timestamptz DEFAULT now(),
  resolved_at timestamptz
);

-- Tabla para las apuestas individuales de los usuarios
CREATE TABLE IF NOT EXISTS bets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_username text NOT NULL, -- referenciado al usuario del album
  fight_id text NOT NULL, -- referenciado a bet_fights.fight_id
  division text NOT NULL,
  picked_pseudo text NOT NULL,
  opponent_pseudo text NOT NULL,
  sobres_amount int NOT NULL CHECK (sobres_amount >= 1),
  status text DEFAULT 'pending', -- 'pending' | 'won' | 'lost' | 'cancelled'
  payout int DEFAULT 0,
  multiplier numeric DEFAULT 4.0, -- payout rate
  created_at timestamptz DEFAULT now(),
  resolved_at timestamptz,
  CONSTRAINT fk_bet_fight FOREIGN KEY (fight_id) REFERENCES bet_fights(fight_id)
);

CREATE INDEX IF NOT EXISTS idx_bets_fight_id ON bets(fight_id);
CREATE INDEX IF NOT EXISTS idx_bets_user ON bets(user_username);

-- Dar permisos si se consulta via un service key no hace falta mucho más
ALTER TABLE bracket_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE bet_fights ENABLE ROW LEVEL SECURITY;
ALTER TABLE bets ENABLE ROW LEVEL SECURITY;

-- Políticas para acceso desde Backend (Service role tiene full pass)
CREATE POLICY "Enable all for service role on bracket_results" ON bracket_results USING (true) WITH CHECK (true);
CREATE POLICY "Enable all for service role on bet_fights" ON bet_fights USING (true) WITH CHECK (true);
CREATE POLICY "Enable all for service role on bets" ON bets USING (true) WITH CHECK (true);
