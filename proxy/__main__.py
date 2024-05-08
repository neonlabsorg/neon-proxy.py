from .neon_proxy_app import NeonProxyApp

if __name__ == "__main__":
    exit_code = NeonProxyApp().start()
    exit(exit_code)
