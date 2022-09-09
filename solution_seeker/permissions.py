from rest_framework import permissions


class IsSolutionProvider(permissions.BasePermission):
    edit_methods = ("PUT", "PATCH")

    def has_permission(self, request, view):
        if request.user.is_solution_provider:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        if obj.user == request.user:
            return True
        return False


class IsManager(permissions.BasePermission):
    # SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')
    view_methods = ("GET",)

    def has_permission(self, request, view):
        if request.user.is_manager and request.method in self.view_methods:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        if obj.user == request.user and request.method in self.view_methods:
            return True
        return False


class IsOwner(permissions.BasePermission):
    # SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')
    edit_methods = ("PUT", "PATCH")

    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        if obj.user == request.user:
            return True
        return False
