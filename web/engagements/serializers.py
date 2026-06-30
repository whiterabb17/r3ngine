from rest_framework import serializers
from .models import Client, Engagement, Assessment, AssessmentScope, AssessmentAsset

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = '__all__'
        read_only_fields = ('uuid', 'created_by', 'created_at', 'updated_at')

class EngagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Engagement
        fields = '__all__'
        read_only_fields = ('uuid', 'created_by', 'created_at', 'updated_at')

class AssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assessment
        fields = '__all__'
        read_only_fields = ('uuid', 'created_by', 'created_at', 'updated_at')

class AssessmentScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentScope
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at', 'updated_at')

class AssessmentAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentAsset
        fields = '__all__'
        read_only_fields = ('uuid', 'created_at')
