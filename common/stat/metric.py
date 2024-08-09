from typing import cast

import aioprometheus.collectors as _base
import aioprometheus.formats.text as _format

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


class StatSummary(_base.Summary, _RemoveValueMixin):
    class _Value(object):
        def __init__(self) -> None:
            self._cnt = 0
            self._sum = 0

        def observe(self, value) -> None:
            self._cnt += 1
            self._sum += value

    def __init__(
        self,
        name: str,
        doc: str,
        const_labels: _base.LabelsType | None = None,
        registry: StatRegistry | None = None,
    ) -> None:
        super().__init__(name, doc, const_labels=const_labels, registry=registry)

    def add(self, labels: _base.LabelsType, value: _base.NumericValueType) -> None:
        """Add a single observation to the summary"""

        value = cast(float | int, value)  # typing check, no runtime behaviour.
        if type(value) not in (float, int):
            raise TypeError("Summary only works with digits (int, float)")

        try:
            v = self.get_value(labels)
        except KeyError:
            v = self._Value()
            self.set_value(labels, v)  # type: ignore

        v.observe(float(value))  # type: ignore

    # https://prometheus.io/docs/instrumenting/writing_clientlibs/#summary
    # A summary MUST have the ``observe`` methods
    observe = add

    def get(self, labels: _base.LabelsType) -> dict[str, _base.NumericValueType]:
        """
        Get a dict of values, containing the sum, count and quantiles,
        matching an arbitrary group of labels.

        :raises: KeyError if an item with matching labels is not present.
        """
        return_data: dict[str, _base.NumericValueType] = dict()
        v: self._Value = self.get_value(labels)  # noqa

        # Set sum and count
        return_data[self.COUNT_KEY] = v._cnt  # noqa:
        return_data[self.SUM_KEY] = v._sum  # noqa:

        return return_data


class _TextFormatter(_format.TextFormatter):

    def marshall(self, registry: StatRegistry) -> str:
        """Marshalls a registry (containing collectors) into a str object"""

        blocks = []
        for i in registry.get_all():
            blocks.append(self.marshall_collector(i))

        # Needs EOF
        blocks.append("")

        return _format.LINE_SEPARATOR_FMT.join(blocks)


def stat_render(registry: StatRegistry) -> MetricStatData:
    formatter = _TextFormatter()
    data = formatter.marshall(registry)
    return MetricStatData(data=data)
