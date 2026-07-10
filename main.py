import binascii
import urllib3
import re
import json
import asyncio
import httpx
import jwt
import os
import traceback
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import my_pb2          
import output_pb2      
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

PLATFORM_MAP = {3: "Facebook", 4: "Guest", 5: "VK", 6: "Huawei", 8: "Google", 11: "X (Twitter)", 13: "AppleId"}

class ConfigUpdateRequest(BaseModel):
    uid: str
    password: str
    release_version: str
    banner_url: str

class RadarRequest(BaseModel):
    lat: float
    lng: float
    distance: float = 9000.0
    ip: str = "103.198.132.204"
    gender: int = 999

def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "saved_uid": "",
            "saved_password": "",
            "dynamic_release_version": "",
            "profile_api_template": ""
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=4)
        return default_config
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {"saved_uid": "", "saved_password": "", "dynamic_release_version": "", "profile_api_template": ""}

def save_config_to_json(data):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def encrypt_message(plaintext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext, 16))

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
    config = load_config()
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            html = f.read()
            
            html = html.replace('value="INITIAL_UID"', f'value="{config.get("saved_uid", "")}"')
            html = html.replace('value="INITIAL_PASSWORD"', f'value="{config.get("saved_password", "")}"')
            html = html.replace('value="INITIAL_VERSION"', f'value="{config.get("dynamic_release_version", "")}"')
            
            raw_template = config.get("profile_api_template", "")
            clean_banner = raw_template.replace("?uid={uid}", "").replace("&uid={uid}", "") if raw_template else ""
            html = html.replace('value="INITIAL_BANNER"', f'value="{clean_banner}"')
            return html
    except FileNotFoundError:
        return "<body>[!] UI HTML asset not found.</body>"

@app.get("/api/get-config")
async def get_config():
    try:
        with open("config.json", "r") as f:
            data = json.load(f)
        
        return {
            "uid": data.get("saved_uid", ""),
            "password": data.get("saved_password", ""),
            "release_version": data.get("dynamic_release_version", "OB54"),
            "banner_url": data.get("profile_api_template", "")
        }
    except FileNotFoundError:
        return {"uid": "", "password": "", "release_version": "OB54", "banner_url": ""}


# === FIXED: ফ্রন্টএন্ডের সেভ কনফিগারের জন্য রুট যুক্ত করা হলো ===
@app.post("/api/update-config")
async def update_config(data: ConfigUpdateRequest):
    try:
        config = {
            "saved_uid": data.uid,
            "saved_password": data.password,
            "dynamic_release_version": data.release_version,
            "profile_api_template": data.banner_url
        }
        save_config_to_json(config)
        return {"status": "success", "message": "Configuration updated successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")


@app.get("/access-jwt")
async def majorlogin_jwt(access_token: str, open_id: str, release_version: str = "OB54"):
    global DYNAMIC_JWT_TOKEN
    
    async with httpx.AsyncClient(verify=False) as client:
        for platform_type in [8, 3, 4, 6]:
            try:
                game_data = my_pb2.GameData()
                game_data.timestamp = "2024-12-05 18:15:32"
                game_data.game_name = "free fire"
                game_data.game_version = 1
                game_data.version_code = "1.128.2"
                game_data.os_info = "Android OS 9"
                game_data.device_type = "Handheld"
                game_data.network_provider = "Verizon Wireless"
                game_data.connection_type = "WIFI"
                game_data.screen_width = 1280
                game_data.screen_height = 960
                game_data.dpi = "240"
                game_data.cpu_info = "ARMv7 VFPv3 NEON"
                game_data.total_ram = 5951
                game_data.gpu_name = "Adreno (TM) 640"
                game_data.gpu_version = "OpenGL ES 3.0"
                game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
                game_data.ip_address = "172.190.111.97"
                game_data.language = "en"
                game_data.open_id = open_id
                game_data.access_token = access_token
                game_data.platform_type = platform_type
                game_data.field_99 = str(platform_type)
                game_data.field_100 = str(platform_type)

                serialized_data = game_data.SerializeToString()
                encrypted_data = encrypt_message(serialized_data)
                headers = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip",
                    "Content-Type": "application/octet-stream",
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": release_version
                }
                
                response = await client.post("https://loginbp.ggblueshark.com/MajorLogin", content=encrypted_data, headers=headers, timeout=5.0)
                if response.status_code == 200:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    token_value = getattr(example_msg, "token", None)
                    
                    if token_value:
                        decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                        DYNAMIC_JWT_TOKEN = str(token_value).strip()
                        
                        config = load_config()
                        config["dynamic_release_version"] = release_version
                        save_config_to_json(config)
                        
                        return {
                            "account_id": decoded_token.get("account_id"),
                            "account_name": decoded_token.get("nickname"),
                            "open_id": open_id,
                            "platform": PLATFORM_MAP.get(decoded_token.get("external_type"), "GUEST"),
                            "region": decoded_token.get("lock_region"),
                            "status": "success",
                            "token": token_value
                        }
            except Exception as platform_err:
                # DEBUG: কোন প্ল্যাটফর্ম কেন ফেইল করছে তা টার্মিনালে দেখাবে
                print(f"[DEBUG] MajorLogin failed for platform {platform_type}: {str(platform_err)}")
                continue
                
    raise HTTPException(status_code=400, detail="Authentication failed on all Garena login platforms.")

@app.get("/token")
async def oauth_guest(uid: str, password: str, release_version: str = "OB54"):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post("https://100067.connect.garena.com/oauth/guest/token/grant", data=payload, headers=headers, timeout=5.0)
            
            # DEBUG: Garena সার্ভার থেকে আসা র স্পেসিফিক রেসপন্স কোড ও মেসেজ প্রিন্ট করা
            if res.status_code != 200:
                print(f"[DEBUG] Garena OAuth Server Rejected request! Status Code: {res.status_code}, Response: {res.text}")
                return JSONResponse(status_code=res.status_code, content={"message": f"Garena Error: {res.text}"})
            
            data = res.json()
            return await majorlogin_jwt(access_token=data.get('access_token'), open_id=data.get('open_id'), release_version=release_version)
        except Exception as e:
            print(f"[DEBUG] Critical Exception in /token endpoint: {str(e)}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan")
async def scan_players(data: RadarRequest):
    global DYNAMIC_JWT_TOKEN
    if not DYNAMIC_JWT_TOKEN:
        raise HTTPException(status_code=401, detail="Active JWT context not found. Authenticate first.")
        
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
            raw_bytes = response.content
            
            if response.status_code in [401, 403]:
                raise HTTPException(status_code=401, detail="Token expired.")
                
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
                        p["profile_img"] = template.replace("{uid}", str(uid))
                    else:
                        p["profile_img"] = None
                        
                return {"status": "success", "players": players}
            raise HTTPException(status_code=422, detail="Protobuf parse failure.")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)