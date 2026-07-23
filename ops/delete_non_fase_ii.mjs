import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("Missing SUPABASE_URL or SUPABASE_KEY");
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

async function main() {
    const { data: fights, error } = await supabase.from('upcoming_fights').select('*');
    if (error) {
        console.error("Error", error);
        return;
    }
    let deleted = 0;
    for (const f of fights) {
        const div = String(f.division || '').toUpperCase();
        const evt = String(f.event_name || '').toUpperCase();
        if (!div.includes("FASE II") && !evt.includes("FASE II")) {
            await supabase.from('upcoming_fights').delete().eq('id', f.id);
            deleted++;
        }
    }
    console.log("Deleted " + deleted + " fights.");
}

main();
