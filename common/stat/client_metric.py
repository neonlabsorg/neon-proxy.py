from .api import MetricStatData
from ..app_data.client import AppDataClient
from ..config.config import Config


class MetricStatClient(AppDataClient):
    def __init__(self, cfg: Config, metric_endpoint: str) -> None:
        super().__init__(cfg)
        self.connect(host=cfg.stat_ip, port=cfg.stat_port, path=metric_endpoint)

    @AppDataClient.method(name="getMetricStatistic")
    async def get_metric_stat(self) -> MetricStatData: ...
