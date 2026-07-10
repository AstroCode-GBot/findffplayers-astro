import binascii
import urllib3
import json
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import httpx

import Find_NearByPlayers_pb2
import blackboxprotobuf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Flexbase Find Nearby Players Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

CONFIG_FILE = "config.json"
DYNAMIC_JWT_TOKEN = ""

class ConfigUpdateRequest(BaseModel):
    jwt: str
    release_version: str
    banner_url: str

class RadarRequest(BaseModel):
    lat: float
    lng: float
    distance: float = 9000.0
    ip: str = "103.198.132.204"
    gender: int = 999

def load_config():
    # এখানে আপনার নতুন ব্যানার এপিআই লিঙ্কটি ডিফল্ট হিসেবে দেওয়া হয়েছে
    default_config = {
        "jwt": "",
        "dynamic_release_version": "OB54",
        "profile_api_template": "https://bannerastro.onrender.com/astro?uid="
    }
    
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=4)
        return default_config
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default_config

def save_config_to_json(data):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# ইনিশিয়াল কনফিগ লোড
config_data = load_config()
DYNAMIC_JWT_TOKEN = config_data.get("jwt", "")

def build_payload(lat, lng, distance, ip, gender):
    msg = Find_NearByPlayers_pb2.CSGetPlayersNearbyReq()
    msg.coor.lat = lat
    msg.coor.lng = lng
    msg.distance = distance
    msg.ip_address = ip
    msg.gender = gender
    
    raw_payload = msg.SerializeToString()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(raw_payload, 16))

def parse_nearby_players_response(decoded_data):
    players_list = []
    items = decoded_data.get('1', [])
    if not isinstance(items, list):
        items = [items]
            
    for item in items:
        if '1' not in item: continue
        acc_info = item['1']
        
        def clean_str(val):
            if isinstance(val, bytes): return val.decode('utf-8', errors='ignore')
            return str(val) if val else 'N/A'

        status_msg = 'N/A'
        if '84' in acc_info and isinstance(acc_info['84'], dict):
            status_msg = clean_str(acc_info['84'].get('9', 'N/A'))

        players_list.append({
            "UID": clean_str(acc_info.get('1')),
            "Name": clean_str(acc_info.get('3', 'Unknown')),
            "Region": clean_str(acc_info.get('5')),
            "Level": acc_info.get('6', 0),
            "Guild": clean_str(acc_info.get('13', 'None')),
            "Signature": status_msg.strip()
        })
    return players_list

@app.get("/", response_class=HTMLResponse)
def read_root():
    try:
        with open("index.php", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<body>[!] UI HTML asset not found.</body>"

@app.get("/api/get-config")
async def get_config():
    config = load_config()
    return {
        "jwt": config.get("jwt", ""),
        "release_version": config.get("dynamic_release_version", "OB54"),
        "banner_url": config.get("profile_api_template", "")
    }

@app.post("/api/update-config")
async def update_config(data: ConfigUpdateRequest):
    global DYNAMIC_JWT_TOKEN
    try:
        config = {
            "jwt": data.jwt.strip(),
            "dynamic_release_version": data.release_version,
            "profile_api_template": data.banner_url.strip()
        }
        save_config_to_json(config)
        DYNAMIC_JWT_TOKEN = data.jwt.strip()
        return {"status": "success", "message": "Config updated successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")

@app.post("/api/scan")
async def scan_players(data: RadarRequest):
    global DYNAMIC_JWT_TOKEN
    if not DYNAMIC_JWT_TOKEN:
        raise HTTPException(status_code=401, detail="Manual Garena JWT Token missing.")
        
    config = load_config()
    payload = build_payload(data.lat, data.lng, data.distance, data.ip, data.gender)
    headers = { 
        'User-Agent': 'UnityPlayer/2022.3.47f1', 
        'Authorization': f'Bearer {DYNAMIC_JWT_TOKEN}', 
        'X-GA': 'v1 1',  
        'ReleaseVersion': config.get("dynamic_release_version", "OB54"), 
        'Content-Type': 'application/x-protobuf', 
        'X-Unity-Version': '2022.3.47f1', 
        'Accept-Encoding': 'deflate, gzip'
    }
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post("https://clientbp.ggpolarbear.com/GetPlayersNearby", headers=headers, content=payload, timeout=10.0)
            
            if response.status_code in [401, 403]:
                raise HTTPException(status_code=401, detail="JWT Token expired.")
                
            raw_bytes = response.content
            decrypted = raw_bytes
            if len(raw_bytes) % 16 == 0 and len(raw_bytes) > 0:
                try:
                    cipher = AES.new(KEY, AES.MODE_CBC, IV)
                    decrypted = unpad(cipher.decrypt(raw_bytes), AES.block_size)
                except: pass
                
            decoded = None
            for i in range(15):
                try:
                    decoded, _ = blackboxprotobuf.decode_message(decrypted[i:])
                    break
                except: continue
                
            if decoded:
                players = parse_nearby_players_response(decoded)
                template = config.get("profile_api_template", "")
                
                for p in players:
                    uid = p.get("UID")
                    if uid and uid != 'N/A' and template:
                        # নিশ্চিত করা হচ্ছে ইউজার ইন্টারফেসে বা কনফিগে {uid} থাকুক বা না থাকুক, লিঙ্ক ঠিকভাবে তৈরি হবে
                        if "{uid}" in template:
                            p["profile_img"] = template.replace("{uid}", str(uid))
                        else:
                            p["profile_img"] = f"{template}{uid}"
                    else:
                        p["profile_img"] = None
                        
                return {"status": "success", "players": players}
            raise HTTPException(status_code=422, detail="Protobuf parsing mismatch.")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Render ডাইনামিকালি PORT এনভায়রনমেন্ট ভ্যারিয়েবল পাস করে
    port = int(os.environ.get("PORT", 8000))
    # Host অবশ্যই 0.0.0.0 দিতে হবে যেন বাইর থেকে অ্যাক্সেস করা যায়
    uvicorn.run(app, host="0.0.0.0", port=port)
