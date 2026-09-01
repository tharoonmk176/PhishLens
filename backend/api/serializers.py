from rest_framework import serializers

class AttachmentSerializer(serializers.Serializer):
    filename = serializers.CharField(required=True)
    content_type = serializers.CharField(required=False, default="application/octet-stream")
    size_bytes = serializers.IntegerField(required=False, default=0)

class EmailInputSerializer(serializers.Serializer):
    message_id = serializers.CharField(required=False, allow_blank=True, default="")
    from_address = serializers.CharField(required=True)
    from_display_name = serializers.CharField(required=False, allow_blank=True, default="")
    reply_to = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    subject = serializers.CharField(required=False, allow_blank=True, default="")
    body_text = serializers.CharField(required=False, allow_blank=True, default="")
    body_html = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    headers_raw = serializers.CharField(required=False, allow_blank=True, default="")
    urls = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    attachments = AttachmentSerializer(many=True, required=False, default=list)

class ChatRequestSerializer(serializers.Serializer):
    message_id = serializers.CharField(required=True)
    user_message = serializers.CharField(required=True)
    analysis_result = serializers.DictField(required=False)

class ReportRequestSerializer(serializers.Serializer):
    message_id = serializers.CharField(required=True)
    analysis_result = serializers.DictField(required=False)

class GmailAnalyzeRequestSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    message_id = serializers.CharField(required=True)
