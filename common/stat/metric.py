import aioprometheus.collectors as _base
import aioprometheus.renderer as _renderer

from common.stat.api import MetricStatData

StatRegistry = _base.Registry


class _RemoveValueMixin:
    def reset(self, labels: _base.LabelsType) -> None:
        if hasattr(self, "values"):
            if labels in self.values:
                del self.values[labels]


class StatGauge(_base.Gauge, _RemoveValueMixin):
    pass


class StatCounter(_base.Counter, _RemoveValueMixin):
    pass


class StatHistogram(_base.Histogram, _RemoveValueMixin):
    pass


class StatSummary(_base.Summary, _RemoveValueMixin):
    pass


def stat_render(registry: StatRegistry) -> MetricStatData:
    data, _ = _renderer.render(registry, ["text/plain"])
    return MetricStatData(data=data.decode("utf-8"))
