import cleanup_logs
import dbcreate

def start_cleanup_logs():
    try:
        threading.Thread(target=cleanup_logs.perform_cleanup, daemon=True).start()
        print("🧹 Log/database cleanup started in background (thread)")
    except Exception as e:
        print(f"❌ Failed to start cleanup_logs: {e}", flush=True)
def signal_handler(sig, frame):
    print("\n🛑 Shutting down HTTP server...", flush=True)

if __name__ == "__main__":
    print("🚀 Running one-shot startup job...")
    dbcreate.init_db()
    cleanup_logs.perform_cleanup()
     
    print("✅ One-shot startup job complete.")