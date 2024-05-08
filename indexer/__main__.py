from .neon_indexer_app import NeonIndexerApp


if __name__ == "__main__":
    exit_code = NeonIndexerApp().start()
    exit(exit_code)
