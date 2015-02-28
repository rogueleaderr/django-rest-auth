from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import serializers
from requests.exceptions import HTTPError
from allauth.socialaccount.helpers import complete_social_login


class SocialLoginSerializer(serializers.Serializer):

    access_token = serializers.CharField(required=True)

    @method_decorator(csrf_exempt)
    def validate_access_token(self, value):
        access_token = value

        view = self.context.get('view')
        request = self.context.get('request')

        if not view:
            raise serializers.ValidationError('View is not defined, pass it ' +
                'as a context variable')
        self.adapter_class = getattr(view, 'adapter_class', None)

        if not self.adapter_class:
            raise serializers.ValidationError('Define adapter_class in view')
        self.adapter = self.adapter_class()
        app = self.adapter.get_provider().get_app(request)
        token = self.adapter.parse_token({'access_token': access_token})
        token.app = app

        try:
            login = self.adapter.complete_login(request, app, token,
                                                response=access_token)
            token.account = login.account
            login.token = token
            complete_social_login(request, login)
        except HTTPError:
            raise serializers.ValidationError('Incorrect value')

        if not login.is_existing:
            login.lookup()
            login.save(request, connect=True)
        self.object = {'user': login.account.user}

        return value
