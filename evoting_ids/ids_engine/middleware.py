from django.http import HttpResponseForbidden
from ids_engine.pipeline import run_ids_pipeline

INTERCEPT_PATHS = ['/accounts/login/', '/vote/', '/admin/', '/api/']
SKIP_PATHS = ['/static/', '/media/', '/favicon.ico', '/admin/jsi18n/']


class LoggingMiddleware:
      def __init__(self, get_response):
          self.get_response = get_response

      def __call__(self, request):
          path = request.path

          if any(path.startswith(skip) for skip in SKIP_PATHS):
              return self.get_response(request)

          should_intercept = any(path.startswith(intercept) for intercept in INTERCEPT_PATHS)

          if not should_intercept:
              return self.get_response(request)

          response = self.get_response(request)

          is_login_path = (
              '/accounts/login/' in request.path or
              request.path.startswith('/admin/login/')
          )
          if is_login_path and request.method == 'POST':
              event_type = 'LOGIN_SUCCESS' if response.status_code == 302 else 'LOGIN_FAIL'
          else:
              event_type = 'GENERIC'

          _, should_block = run_ids_pipeline(request, event_type=event_type)

          if should_block:
              return HttpResponseForbidden("Access denied by IDS.")

          return response