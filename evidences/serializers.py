from rest_framework import serializers
from evidences.models import Evidence
from cases.models import Case


class EvidenceSerializer(serializers.ModelSerializer):
    """
    Evidence Serializer
    Used to send json data to the front end for an evidence.
    """

    dump_linked_case_name = serializers.SerializerMethodField()

    class Meta:
        model = Evidence
        fields = "__all__"
        extra_fields = ["dump_linked_case_name"]

    def get_dump_linked_case_name(self, obj):
        # Return the name of the linked case instead of the id
        return obj.dump_linked_case.case_name


class AnalysisStartSerializer(serializers.Serializer):
    dump_id = serializers.IntegerField()
