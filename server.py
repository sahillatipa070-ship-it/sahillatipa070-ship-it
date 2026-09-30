"""VASUDHA local application: standard-library HTTP server + SQLite API."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
DATA = ROOT / "data"
UPLOADS = DATA / "uploads"
DB = DATA / "waterscope.sqlite3"
HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", "8000"))

GEO_CACHE = {}
GEO_LOCK = threading.Lock()
GEO_LAST_REQUEST = 0.0
SEARCH_LOCK = threading.Lock()
SEARCH_LAST_REQUEST = 0.0

def connect():
    DATA.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    UPLOADS.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, organization TEXT DEFAULT 'Watershed Team', account_type TEXT NOT NULL DEFAULT 'user', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, original_name TEXT NOT NULL, category TEXT DEFAULT 'Field Photo', location TEXT DEFAULT '', latitude REAL, longitude REAL, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, stage TEXT NOT NULL DEFAULT 'Observation', intervention_id TEXT);
        CREATE TABLE IF NOT EXISTS interventions (id TEXT PRIMARY KEY, type TEXT NOT NULL, status TEXT NOT NULL, area TEXT NOT NULL, date TEXT NOT NULL, impact INTEGER DEFAULT 50, icon TEXT DEFAULT '◈', latitude REAL, longitude REAL, details TEXT NOT NULL DEFAULT '');
        """)
        user_cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
        if "account_type" not in user_cols:
            c.execute("ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'user'")
        intervention_cols = {r[1] for r in c.execute("PRAGMA table_info(interventions)")}
        if "latitude" not in intervention_cols: c.execute("ALTER TABLE interventions ADD COLUMN latitude REAL")
        if "longitude" not in intervention_cols: c.execute("ALTER TABLE interventions ADD COLUMN longitude REAL")
        if "details" not in intervention_cols: c.execute("ALTER TABLE interventions ADD COLUMN details TEXT NOT NULL DEFAULT ''")
        photo_cols = {r[1] for r in c.execute("PRAGMA table_info(photos)")}
        if "stage" not in photo_cols: c.execute("ALTER TABLE photos ADD COLUMN stage TEXT NOT NULL DEFAULT 'Observation'")
        if "intervention_id" not in photo_cols: c.execute("ALTER TABLE photos ADD COLUMN intervention_id TEXT")

def asdict(row):
    return dict(row) if row else None

class Handler(BaseHTTPRequestHandler):
    server_version = "VASUDHA/1.0"

    def log_message(self, *_):
        pass

    def send_json(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 14 * 1024 * 1024:
            raise ValueError("Request is too large (14 MB maximum).")
        return json.loads(self.rfile.read(size) or b"{}")

    def session_user(self, c):
        cookie = SimpleCookie()
        try: cookie.load(self.headers.get("Cookie", ""))
        except Exception: pass
        token = cookie.get("waterscope_session").value if cookie.get("waterscope_session") else ""
        row = c.execute("SELECT users.* FROM users JOIN sessions ON users.id=sessions.user_id WHERE sessions.token=?", (token,)).fetchone()
        return asdict(row)

    def require_user(self, c, organization=False):
        user = self.session_user(c)
        if not user:
            self.send_json({"error": "Sign in to access this section."}, 401)
            return None
        if organization and user.get("account_type") != "organization":
            self.send_json({"error": "Photo uploads are available to organization accounts."}, 403)
            return None
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        if path.startswith("/api/"):
            with connect() as c:
                if path == "/api/health":
                    return self.send_json({"ok": True, "app": "VASUDHA"})
                if path == "/api/me":
                    user = self.session_user(c)
                    return self.send_json({"user": {"name": user["name"], "email": user["email"], "organization": user["organization"], "accountType": user["account_type"]} if user else None})
                if path == "/api/interventions":
                    if not self.require_user(c): return
                    return self.send_json([dict(r) for r in c.execute("SELECT * FROM interventions ORDER BY date DESC")])
                if path == "/api/photos":
                    if not self.require_user(c, organization=True): return
                    return self.send_json([dict(r) for r in c.execute("SELECT id,filename,original_name,category,location,latitude,longitude,uploaded_at,stage,intervention_id FROM photos ORDER BY id DESC")])
                if path == "/api/analytics":
                    if not self.require_user(c): return
                    interventions = [dict(r) for r in c.execute("SELECT * FROM interventions")]
                    photos = c.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
                    return self.send_json({"interventions": len(interventions), "photos": photos, "interventionRows": interventions})
                if path == "/api/reports/export":
                    if not self.require_user(c): return
                    return self.export_report(c, query.get("format", ["csv"])[0])
                if path == "/api/geo":
                    if not self.require_user(c): return
                    return self.geo_data(c, query)
                if path == "/api/search":
                    if not self.require_user(c): return
                    return self.search_location(query.get("q", [""])[0])
            return self.send_json({"error": "Not found"}, 404)
        self.serve_file(path)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            payload = self.body()
            if path == "/api/auth/register":
                name = str(payload.get("name", "")).strip()
                email = str(payload.get("email", "")).strip().lower()
                password = str(payload.get("password", ""))
                org = str(payload.get("organization", "Watershed Team")).strip() or "Watershed Team"
                if not name or "@" not in email or len(password) < 8:
                    return self.send_json({"error": "Enter your name, a valid email, and a password with at least 8 characters."}, 400)
                account_type = str(payload.get("accountType", "user"))
                if account_type not in ("user", "organization"):
                    return self.send_json({"error": "Choose a valid account type."}, 400)
                if account_type == "organization" and not payload.get("organization", "").strip():
                    return self.send_json({"error": "Enter your organization name."}, 400)
                salt = secrets.token_hex(16)
                digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240000).hex()
                with connect() as c:
                    try:
                        cur = c.execute("INSERT INTO users(name,email,salt,password_hash,organization,account_type) VALUES(?,?,?,?,?,?)", (name,email,salt,digest,org,account_type))
                    except sqlite3.IntegrityError:
                        return self.send_json({"error": "An account with that email already exists."}, 409)
                    return self.create_session(c, cur.lastrowid, name, email, org, account_type)
            if path == "/api/auth/login":
                email, password = str(payload.get("email", "")).lower().strip(), str(payload.get("password", ""))
                with connect() as c:
                    row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                    if not row or not hmac.compare_digest(row["password_hash"], hashlib.pbkdf2_hmac("sha256", password.encode(), row["salt"].encode(), 240000).hex()):
                        return self.send_json({"error": "Email or password is incorrect."}, 401)
                    if payload.get("accountType", "user") != row["account_type"]:
                        return self.send_json({"error": "Choose the correct account type for this login."}, 403)
                    return self.create_session(c, row["id"], row["name"], row["email"], row["organization"], row["account_type"])
            if path == "/api/auth/logout":
                token = self.headers.get("Cookie", "").replace("waterscope_session=", "").split(";", 1)[0]
                with connect() as c: c.execute("DELETE FROM sessions WHERE token=?", (token,))
                self.send_response(200); self.send_header("Set-Cookie", "waterscope_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"); self.end_headers(); return
            if path == "/api/photos":
                with connect() as c:
                    user = self.require_user(c, organization=True)
                if not user: return
                name = str(payload.get("name", "photo.jpg"))[:160]
                mime = str(payload.get("mime", "image/jpeg"))
                raw = base64.b64decode(str(payload.get("data", "")).split(",")[-1], validate=False)
                if not raw or len(raw) > 10 * 1024 * 1024: return self.send_json({"error": "Choose an image smaller than 10 MB."}, 400)
                if mime not in ("image/jpeg", "image/png", "image/webp"): return self.send_json({"error": "Only JPG, PNG and WebP images are supported."}, 400)
                try:
                    lat = float(payload.get("latitude")); lon = float(payload.get("longitude"))
                except (TypeError, ValueError):
                    return self.send_json({"error": "GPS latitude and longitude are required."}, 400)
                if not (-90 <= lat <= 90 and -180 <= lon <= 180): return self.send_json({"error": "Enter valid latitude and longitude coordinates."}, 400)
                stage = str(payload.get("stage", "Observation"))
                if stage not in ("Before", "After", "Observation"): return self.send_json({"error": "Choose Before, After, or Observation for this photo."}, 400)
                intervention_id = str(payload.get("interventionId", "")).strip() or None
                if stage in ("Before", "After") and not intervention_id:
                    return self.send_json({"error": "Link a before/after photo to an intervention."}, 400)
                if intervention_id:
                    with connect() as c:
                        if not c.execute("SELECT 1 FROM interventions WHERE id=?", (intervention_id,)).fetchone():
                            return self.send_json({"error": "The selected intervention could not be found."}, 400)
                ext = mimetypes.guess_extension(mime) or ".img"
                filename = secrets.token_hex(12) + ext
                (UPLOADS / filename).write_bytes(raw)
                with connect() as c:
                    cur = c.execute("INSERT INTO photos(filename,original_name,category,location,latitude,longitude,user_id,stage,intervention_id) VALUES(?,?,?,?,?,?,?,?,?)", (filename,name,str(payload.get("category","Field Photo")),str(payload.get("location","")),lat,lon,user["id"] if user else None,stage,intervention_id))
                    return self.send_json({"id": cur.lastrowid, "filename": name, "message": "Photo uploaded."}, 201)
            if path == "/api/photos/update":
                with connect() as c:
                    user = self.require_user(c, organization=True)
                    if not user: return
                    try: photo_id = int(payload.get("id"))
                    except (TypeError, ValueError): return self.send_json({"error": "Choose a valid photo."}, 400)
                    stage = str(payload.get("stage", "Observation"))
                    if stage not in ("Before", "After", "Observation"): return self.send_json({"error": "Choose Before, After, or Observation."}, 400)
                    intervention_id = str(payload.get("interventionId", "")).strip() or None
                    if stage in ("Before", "After") and not intervention_id: return self.send_json({"error": "Link a before/after photo to an intervention."}, 400)
                    if intervention_id and not c.execute("SELECT 1 FROM interventions WHERE id=?", (intervention_id,)).fetchone(): return self.send_json({"error": "The selected intervention could not be found."}, 400)
                    cur = c.execute("UPDATE photos SET stage=?,intervention_id=? WHERE id=?", (stage,intervention_id,photo_id))
                    if not cur.rowcount: return self.send_json({"error": "The photo could not be found."}, 404)
                    return self.send_json({"id": photo_id, "stage": stage, "interventionId": intervention_id, "message": "Photo classification saved."})
            if path == "/api/interventions":
                with connect() as c:
                    if not self.require_user(c): return
                kind = str(payload.get("type", "")).strip(); area = str(payload.get("area", "")).strip()
                if not kind or not area: return self.send_json({"error": "Add an intervention type and area."}, 400)
                if kind not in ("Afforestation", "Check Dam", "Contour Trenching", "Water Harvesting Structure", "Other field intervention"):
                    return self.send_json({"error": "Choose a valid intervention type."}, 400)
                status = str(payload.get("status", "Planned"))
                if status not in ("Completed", "Ongoing", "Planned"):
                    return self.send_json({"error": "Choose Completed, Ongoing, or Planned status."}, 400)
                lat, lon = float(payload.get("latitude")), float(payload.get("longitude"))
                if not (6.4 <= lat <= 37.2 and 68.0 <= lon <= 97.5): return self.send_json({"error": "Choose intervention coordinates inside India."}, 400)
                row = {"id": "INT-" + secrets.token_hex(3).upper(), "type": kind, "status": status, "area": area, "date": payload.get("date") or time.strftime("%Y-%m-%d"), "impact": None, "icon": "◈", "latitude":lat, "longitude":lon, "details": str(payload.get("details", "")).strip()[:2000]}
                with connect() as c: c.execute("INSERT INTO interventions(id,type,status,area,date,impact,icon,latitude,longitude,details) VALUES(:id,:type,:status,:area,:date,:impact,:icon,:latitude,:longitude,:details)", row)
                return self.send_json(row, 201)
            return self.send_json({"error": "Not found"}, 404)
        except (ValueError, TypeError, KeyError) as exc:
            return self.send_json({"error": str(exc) or "Invalid request."}, 400)

    def create_session(self, c, user_id, name, email, organization, account_type):
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)", (token,user_id,int(time.time())))
        raw = json.dumps({"user": {"name":name,"email":email,"organization":organization,"accountType":account_type}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw)))
        self.send_header("Set-Cookie", f"waterscope_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"); self.end_headers(); self.wfile.write(raw)

    def export_report(self, c, fmt):
        rows = [dict(r) for r in c.execute("SELECT * FROM interventions ORDER BY date DESC")]
        if fmt == "json":
            raw = json.dumps({"generatedAt": time.strftime("%Y-%m-%d %H:%M UTC"), "source": "VASUDHA records entered by the signed-in team", "interventions": rows}, indent=2).encode()
            kind, filename = "application/json", "waterscope-report.json"
        else:
            import csv, io
            out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=["id","type","status","area","date","impact"]); writer.writeheader(); writer.writerows([{k:r[k] for k in writer.fieldnames} for r in rows])
            raw = out.getvalue().encode(); kind, filename = "text/csv; charset=utf-8", "waterscope-interventions.csv"
        self.send_response(200); self.send_header("Content-Type", kind); self.send_header("Content-Disposition", f'attachment; filename="{filename}"'); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def geo_data(self, c, query):
        kind = query.get("type", ["landuse"])[0]
        try:
            south, west, north, east = [float(x) for x in query.get("bbox", [""])[0].split(",")]
        except (ValueError, IndexError):
            return self.send_json({"error": "A valid map bounding box is required."}, 400)
        if not (-90 <= south < north <= 90 and -180 <= west < east <= 180) or north - south > .55 or east - west > .55:
            return self.send_json({"error": "Zoom in to an area no larger than about 60 km to load detailed map features."}, 400)
        center_lat, center_lon = (south + north) / 2, (west + east) / 2
        if not (6.4 <= center_lat <= 37.2 and 68.0 <= center_lon <= 97.5):
            return self.send_json({"error": "Live map features are limited to India. Move the map back over India."}, 400)
        if kind == "interventions":
            rows = [dict(r) for r in c.execute("SELECT * FROM interventions WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ?", (south,north,west,east))]
            features = [{"type":"Feature","geometry":{"type":"Point","coordinates":[r["longitude"],r["latitude"]]},"properties":{**r,"source":"VASUDHA field record"}} for r in rows]
            return self.send_json({"type":"FeatureCollection","features":features,"source":"VASUDHA field records","updated":"Local records"})
        if kind == "photos":
            user = self.require_user(c, organization=True)
            if not user: return
            rows = [dict(r) for r in c.execute("SELECT id,filename,original_name,category,location,latitude,longitude,uploaded_at,stage,intervention_id FROM photos WHERE latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ?", (south,north,west,east))]
            features = [{"type":"Feature","geometry":{"type":"Point","coordinates":[r["longitude"],r["latitude"]]},"properties":{**r,"source":"Organization GPS photo","type":"Geotagged photo"}} for r in rows]
            return self.send_json({"type":"FeatureCollection","features":features,"source":"Organization GPS photos","updated":"Local records"})
        filters = {
            "landuse": 'way["landuse"~"forest|farmland|farmyard|orchard|vineyard|meadow|grass|allotments|residential|commercial|retail|industrial|construction|quarry|landfill|brownfield|reservoir"]({bbox});way["natural"~"water|wood|wetland|scrub|grassland|bare_rock|sand"]({bbox});way["waterway"~"river|stream|canal"]({bbox});',
            "drainage": 'way["waterway"~"river|stream|canal|drain|ditch"]({bbox});',
            "vegetation": 'way["landuse"~"forest|orchard|vineyard|meadow|grass"]({bbox});way["natural"~"wood|tree_row|scrub"]({bbox});',
            "water": 'way["natural"="water"]({bbox});way["landuse"="reservoir"]({bbox});way["waterway"="riverbank"]({bbox});'
        }
        if kind not in filters:
            return self.send_json({"error": "No verified public map-data layer is configured for this analysis."}, 422)
        bbox = f"{south:.5f},{west:.5f},{north:.5f},{east:.5f}"
        cache_key = (kind, bbox)
        now = time.time()
        cached = GEO_CACHE.get(cache_key)
        if cached and now - cached[0] < 1800:
            return self.send_json(cached[1])
        global GEO_LAST_REQUEST
        with GEO_LOCK:
            delay = 0.8 - (time.time() - GEO_LAST_REQUEST)
            if delay > 0: time.sleep(delay)
            GEO_LAST_REQUEST = time.time()
        q = f"[out:json][timeout:10];({filters[kind].format(bbox=bbox)});out tags geom;"
        req = urllib.request.Request("https://overpass-api.de/api/interpreter", data=urllib.parse.urlencode({"data":q}).encode(), headers={"User-Agent":"VASUDHALocal/1.0 (watershed map viewer)","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"})
        try:
            with urllib.request.urlopen(req, timeout=12) as response: result = json.loads(response.read())
        except Exception:
            self.send_json({"error": "OpenStreetMap is busy or unreachable. Retry in a moment, or zoom in for a smaller area."}, 502); return
        features=[]
        for item in result.get("elements", []):
            coords=[(p["lon"],p["lat"]) for p in item.get("geometry", []) if "lat" in p and "lon" in p]
            if len(coords)<2: continue
            tags=item.get("tags", {})
            is_area=coords[0]==coords[-1] or "landuse" in tags or tags.get("natural") in ("water","wood","wetland","scrub","grassland") or tags.get("leisure") in ("park","nature_reserve")
            if is_area and coords[0]!=coords[-1]: coords.append(coords[0])
            features.append({"type":"Feature","geometry":{"type":"Polygon","coordinates":[coords]} if is_area else {"type":"LineString","coordinates":coords},"properties":{"osm_id":item.get("id"),**tags}})
        data={"type":"FeatureCollection","features":features,"source":"© OpenStreetMap contributors","updated":result.get("osm3s",{}).get("timestamp_osm_base", "")}
        GEO_CACHE[cache_key]=(time.time(),data)
        return self.send_json(data)

    def search_location(self, q):
        q = q.strip()[:160]
        if not q: return self.send_json({"error":"Enter a place name or coordinates."},400)
        if "," in q:
            try:
                lat,lon=[float(x.strip()) for x in q.split(",",1)]
                if -90<=lat<=90 and -180<=lon<=180:
                    if not (6.4<=lat<=37.2 and 68.0<=lon<=97.5): return self.send_json({"error":"Choose coordinates inside India."},400)
                    return self.send_json({"lat":lat,"lon":lon,"label":q,"source":"Coordinates"})
            except ValueError: pass
        cache_key=("search",q.lower())
        if cache_key in GEO_CACHE: return self.send_json(GEO_CACHE[cache_key][1])
        global SEARCH_LAST_REQUEST
        with SEARCH_LOCK:
            delay=1.1-(time.time()-SEARCH_LAST_REQUEST)
            if delay>0: time.sleep(delay)
            SEARCH_LAST_REQUEST=time.time()
        req=urllib.request.Request("https://nominatim.openstreetmap.org/search?"+urllib.parse.urlencode({"q":q,"format":"jsonv2","limit":1,"polygon_geojson":1,"polygon_threshold":0.002}),headers={"User-Agent":"VASUDHALocal/1.0 (user-triggered map search)"})
        try:
            with urllib.request.urlopen(req,timeout=15) as response: results=json.loads(response.read())
        except Exception as exc:
            self.send_json({"error":f"Map search is temporarily unavailable: {exc}"},502); return
        if not results: return self.send_json({"error":"No matching location was found."},404)
        place=results[0]
        result={"lat":float(place["lat"]),"lon":float(place["lon"]),"label":place.get("display_name",""),"source":"OpenStreetMap Nominatim","boundary":place.get("geojson")}
        if place.get("boundingbox"):
            result["bounds"]=[float(value) for value in place["boundingbox"]]
        GEO_CACHE[cache_key]=(time.time(),result)
        return self.send_json(result)

    def serve_file(self, path):
        if path.startswith("/uploads/"):
            with connect() as c:
                if not self.require_user(c, organization=True): return
            file = (UPLOADS / Path(path).name).resolve()
            if not str(file).startswith(str(UPLOADS.resolve())) or not file.is_file():
                self.send_error(404); return
            content = file.read_bytes(); mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            self.send_response(200); self.send_header("Content-Type", mime); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content); return
        rel = "index.html" if path == "/" else path.lstrip("/")
        file = (PUBLIC / rel).resolve()
        if not str(file).startswith(str(PUBLIC.resolve())) or not file.is_file():
            self.send_error(404); return
        content = file.read_bytes(); mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or "javascript" in mime else "")); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content)

if __name__ == "__main__":
    init_db()
    print(f"VASUDHA running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
