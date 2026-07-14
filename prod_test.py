import requests
import json
import time
import random
import string

BASE_URL = "https://bellatorrpg.online/api"

def generate_pseudonym(): return "ZZTEST_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
def generate_player_key(): return "KEY_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

def register_user(pseudonym, player_key):
    payload = {
        "pseudonimo": pseudonym,
        "player_key": player_key,
        "country_code": "US",
        "fingerprint": "fake_hw_" + pseudonym
    }
    r = requests.post(f"{BASE_URL}/album/register", json=payload)
    if r.status_code != 200:
        raise Exception(f"Register failed for {pseudonym}: {r.status_code} {r.text}")
    return r.json()["token"]

def get_me(token):
    r = requests.get(f"{BASE_URL}/album/me", headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        raise Exception(f"Me failed: {r.status_code} {r.text}")
    return r.json()

def admin_grant(admin_token, pseudonym, packs):
    r = requests.post(f"{BASE_URL}/admin/album/grant-packs", 
                      headers={"Authorization": f"Bearer {admin_token}"},
                      json={"pseudonimo": pseudonym, "packs": packs})
    if r.status_code != 200:
        raise Exception(f"Grant packs failed for {pseudonym}: {r.status_code} {r.text}")

def open_pack(token):
    r = requests.post(f"{BASE_URL}/album/open-pack?use_bonus_pack=true", headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        raise Exception(f"Open pack failed: {r.status_code} {r.text}")
    return r.json()

def get_collection(token):
    r = requests.get(f"{BASE_URL}/album/collection", headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        raise Exception(f"Collection failed: {r.status_code} {r.text}")
    return r.json()

def get_admin_users(admin_token):
    r = requests.get(f"{BASE_URL}/admin/album/users", headers={"Authorization": f"Bearer {admin_token}"})
    if r.status_code != 200:
        raise Exception(f"Admin users failed: {r.status_code} {r.text}")
    return r.json()

def main():
    with open("admin_token.txt", "r") as f:
        admin_token = f.read().strip()

    print("--- 1. Registering Users ---")
    p1 = generate_pseudonym()
    k1 = generate_player_key()
    t1 = register_user(p1, k1)
    
    p2 = generate_pseudonym()
    k2 = generate_player_key()
    t2 = register_user(p2, k2)
    
    print(f"Registered {p1} and {p2}")

    print("--- 2. Checking Initial Status ---")
    me1 = get_me(t1)
    me2 = get_me(t2)
    print(f"{p1} bonus_packs: {me1.get('bonus_packs', 0)}")
    print(f"{p2} bonus_packs: {me2.get('bonus_packs', 0)}")

    print("--- 3. Checking Admin User List ---")
    admin_users = get_admin_users(admin_token)
    found1 = next((u for u in admin_users if u["pseudonimo"] == p1), None)
    found2 = next((u for u in admin_users if u["pseudonimo"] == p2), None)
    print(f"{p1} in admin list: {found1 is not None} (ID length: {len(found1['user_id']) if found1 else 'N/A'})")
    print(f"{p2} in admin list: {found2 is not None} (ID length: {len(found2['user_id']) if found2 else 'N/A'})")

    print("--- 4. Granting Packs ---")
    admin_grant(admin_token, p1, 12)
    admin_grant(admin_token, p2, 12)
    
    me1 = get_me(t1)
    me2 = get_me(t2)
    print(f"{p1} bonus_packs after grant: {me1.get('bonus_packs', 0)}")
    print(f"{p2} bonus_packs after grant: {me2.get('bonus_packs', 0)}")

    print("--- 5. Opening Packs for Duplicates & Exchange ---")
    def get_dupes(token):
        coll = get_collection(token)
        return {item["id"]: item["quantity"] - 1 for item in coll if item["quantity"] > 1}, {item["id"] for item in coll}

    for t, p in [(t1, p1), (t2, p2)]:
        for _ in range(12):
            open_pack(t)
    
    dupes1, owned1 = get_dupes(t1)
    dupes2, owned2 = get_dupes(t2)
    print(f"{p1} duplicates: {list(dupes1.keys())}")
    print(f"{p2} duplicates: {list(dupes2.keys())}")

    # Find tradeable candidates
    # A has dupe A_d that B lacks. B has dupe B_d that A lacks.
    trade_offered = None
    trade_wanted = None
    
    for d1 in dupes1:
        if d1 not in owned2:
            for d2 in dupes2:
                if d2 not in owned1:
                    trade_offered = d1
                    trade_wanted = d2
                    break
        if trade_offered: break

    if not trade_offered:
        print("Could not find suitable trade candidates within 12 packs. Retrying with a few more if status allows, or ending.")
        # Attempt minimal extra if they have space? Requirement says cap 12. Skip if failed.
        print("FAILED: No dirigible trade possible from 12 packs.")
        return

    print(f"Trade Candidate: {p1} offers {trade_offered} for {trade_wanted} from {p2}")

    print("--- 6. Directed Trade ---")
    payload = {
        "offered_sticker_id": trade_offered,
        "wanted_sticker_id": trade_wanted,
        "target_pseudonimo": p2
    }
    r = requests.post(f"{BASE_URL}/album/trades", headers={"Authorization": f"Bearer {t1}"}, json=payload)
    if r.status_code != 200:
        raise Exception(f"Create trade failed: {r.status_code} {r.text}")
    
    trade_id = r.json()["id"]

    print("--- 7. Receiving Trade ---")
    r = requests.get(f"{BASE_URL}/album/trades", headers={"Authorization": f"Bearer {t2}"})
    trades = r.json()
    my_trade = next((tr for tr in trades if tr["id"] == trade_id), None)
    if not my_trade:
        raise Exception("Trade not visible to recipient")
    print(f"Trade {trade_id} visible to {p2}")

    print("--- 8. Accepting Trade ---")
    coll1_pre = {i["id"]: i["quantity"] for i in get_collection(t1)}
    coll2_pre = {i["id"]: i["quantity"] for i in get_collection(t2)}

    r = requests.post(f"{BASE_URL}/album/trades/accept", headers={"Authorization": f"Bearer {t2}"}, json={"trade_id": trade_id})
    if r.status_code != 200:
        raise Exception(f"Accept trade failed: {r.status_code} {r.text}")
    
    print("Trade accepted.")

    coll1_post = {i["id"]: i["quantity"] for i in get_collection(t1)}
    coll2_post = {i["id"]: i["quantity"] for i in get_collection(t2)}

    print(f"Validation:")
    print(f"{p1} {trade_offered}: {coll1_pre.get(trade_offered)} -> {coll1_post.get(trade_offered)}")
    print(f"{p1} {trade_wanted}: {coll1_pre.get(trade_wanted, 0)} -> {coll1_post.get(trade_wanted)}")
    print(f"{p2} {trade_offered}: {coll2_pre.get(trade_offered, 0)} -> {coll2_post.get(trade_offered)}")
    print(f"{p2} {trade_wanted}: {coll2_pre.get(trade_wanted)} -> {coll2_post.get(trade_wanted)}")

    success = (
        coll1_post[trade_offered] == coll1_pre[trade_offered] - 1 and
        coll1_post[trade_wanted] == coll1_pre.get(trade_wanted, 0) + 1 and
        coll2_post[trade_offered] == coll2_pre.get(trade_offered, 0) + 1 and
        coll2_post[trade_wanted] == coll2_pre[trade_wanted] - 1
    )

    if success:
        print("SUCCESS: Admin pack grants and directed trade/accept with inventory mutation work end-to-end on production.")
    else:
        print("FAILURE: Inventory did not update correctly.")

if __name__ == "__main__":
    main()
