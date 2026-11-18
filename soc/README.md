# 🛡️ Dedicated IGYR Security Operations Centre (SOC) Server

This folder contains the **independent SOC server** that runs on a separate server / Render web service.

---

## 🔑 Login Credentials
* **SOC ID:** `igyr`
* **Password:** `cutiee`

---

## ⚙️ Environment Variables for Render (SOC Web Service)
When deploying this SOC service on Render, add these Environment Variables:

| Key | Value | Description |
|---|---|---|
| `SOC_USER` | `igyr` | SOC Operator Login ID |
| `SOC_PASSWORD` | `cutiee` | SOC Operator Password |
| `MONGO_URI` | `mongodb+srv://auradispatch2026_db_user:611LdmEjTS7WeqKW@cluster0.z9xcllt.mongodb.net/?appName=Cluster0` | Shared MongoDB connection for platform ON/OFF synchronization |
| `MAIN_SERVER_URL` | `https://igyr-india-get-your-result.onrender.com` | Target main platform URL monitored by this SOC |
| `PYTHON_VERSION` | `3.9.16` | Python runtime version |

---

## 🚀 How to Run Locally
```bash
cd soc
pip install -r requirements.txt
python app.py
```
Default URL: `http://localhost:5006/` or `http://localhost:5006/soc`

---

## ☁️ How to Deploy on Render as a Separate Web Service
1. In Render, click **New + > Web Service**.
2. Connect your Git repository.
3. Configure the settings:
   - **Name:** `igyr-soc-server`
   - **Root Directory:** `soc`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Health Check Path:** `/health`
4. Add the environment variables listed above.
5. Deploy!
