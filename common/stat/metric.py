import aioprometheus.collectors as _base

StatRegistry = _base.Registry


class _RemoveValueMixin:
    def reset(self, labels: _base.LabelsType) -> None:
        if labels in self.values:  # NOQA
            del self.values[labels]  # NOQA


class StatGauge(_base.Gauge, _RemoveValueMixin):
    pass


class StatCounter(_base.Counter, _RemoveValueMixin):
    pass


class StatHistogram(_base.Histogram, _RemoveValueMixin):
    pass


class StatSummary(_base.Summary, _RemoveValueMixin):
    pass
