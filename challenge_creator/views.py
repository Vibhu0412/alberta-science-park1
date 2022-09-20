from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet
from challenge_creator.serializers import ChallengeStatementSerializer, ListRetrieveChallengeStatementSerializer, \
    ListCommentSerializer, PostCommentSerializer
    # PersonalInformationSerializer
from api.models import  PersonalInformation
from .models import ChallengeStatement, Comment
from .permissions import IsChallengeCreator, IsOwner, IsManager
from .renderers import ChallengeCreatorRenderer
from rest_framework import status
from rest_framework.response import Response
from api.models import User,PersonalInformation
from rest_framework.views import APIView

# Create your views here
class ChallengeStatementViewSet(ModelViewSet):
    serializer_class = ChallengeStatementSerializer
    queryset = ChallengeStatement.objects.all().order_by('-created_at')
    # permission_classes = [IsAuthenticated, IsChallengeCreator | IsOwner]
    # permission_classes = [IsAuthenticated, IsChallengeCreator | IsManager]
    # pagination_class = PageNumberPagination
    # page_size = 2
    permission_classes = [IsAuthenticated, IsOwner]
    renderer_classes = [ChallengeCreatorRenderer]

    def create(self, request, *args, **kwargs):
        challenge_data = self.request.data
        challenge_data['user'] = self.request.user.id
        print("CHALLENGE_DATA ===== ", challenge_data)
        serializer = self.serializer_class(data=challenge_data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Setting User to the Authenticated user
        request.data["user"] = self.request.user.id
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ListRetrieveChallengeStatementSerializer(instance=instance)
        return Response(serializer.data)

    ##### List's Submitted Challenges .....
    def list(self, request, *args, **kwargs):
        # personal_info = PersonalInformation.objects.get(user_id=request.user.id)
        # print(personal_info)
        # serializer_info = PersonalInformationSerializer(personal_info)
        # print('SERIALIZER',serializer_info.data)
        # b_info =
        # print('INFO===',b_info)
        # print(self.queryset)
        # pid = PersonalInformation.objects.get(user=request.user)
        # print(pid.full_name)

        # queryset = ChallengeStatement.objects.filter(post_type = 'Active' ,
        #                                              is_archieve=False).order_by('-created_at')

        if request.GET.get('order_by') == "New":
            queryset = ChallengeStatement.objects.filter(post_type = 'Active').order_by('-created_at')
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = ListRetrieveChallengeStatementSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            else:
                serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.GET.get('order_by') == "Old":
            queryset = ChallengeStatement.objects.filter(post_type='Active').order_by('created_at')
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = ListRetrieveChallengeStatementSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            else:
                serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        else:
            queryset = ChallengeStatement.objects.filter(post_type='Active').order_by('created_at')
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = ListRetrieveChallengeStatementSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            else:
                serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        # data ={
        #     'challenges':serializer.data,
        #     # 'first_name': pid.full_name()
        # }

    # @action(detail=False, methods=['get'])
    # def list_my_challenges(self, request, *args, **kwargs):
    #     list_my_challenges_queryset= ChallengeStatement.objects.filter(user=request.user,
    #                                         is_archieve=False,post_type = 'Active').order_by('-created_at')
    #     serializer = ListRetrieveChallengeStatementSerializer(list_my_challenges_queryset, many=True)
    #     return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def list_my_challenges(self, request, *args, **kwargs):
        list_my_challenges_queryset = ChallengeStatement.objects.filter(user=request.user).order_by('-created_at')
        print(list_my_challenges_queryset)
        serializer = ListRetrieveChallengeStatementSerializer(list_my_challenges_queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def list_draft_challenges(self, request, *args, **kwargs):
        queryset = ChallengeStatement.objects.filter(user=request.user,
                                                     post_type='Draft').order_by('-created_at')
        serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def list_archived_challenges(self, request, *args, **kwargs):
        queryset = ChallengeStatement.objects.filter(user=request.user,
                                                     is_archieve=True).order_by('-created_at')
        serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
        return Response(serializer.data)


class PushArchieveApiView(APIView):
    permission_classes = [IsAuthenticated, IsOwner]
    renderer_classes = [ChallengeCreatorRenderer]
    def get(self, request, pk,*args, **kwargs):
        queryset = ChallengeStatement.objects.get(id=pk)
        queryset.is_archieve=True
        queryset.save()
        # serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
        return Response({'msg':'Post Archieved.'}, status=status.HTTP_200_OK)

class PushUnArchieveApiView(APIView):
    permission_classes = [IsAuthenticated, IsOwner]
    renderer_classes = [ChallengeCreatorRenderer]
    def get(self, request, pk,*args, **kwargs):
        queryset = ChallengeStatement.objects.get(id=pk)
        queryset.is_archieve=False
        queryset.save()
        # serializer = ListRetrieveChallengeStatementSerializer(queryset, many=True)
        return Response({'msg':'Post UnArchieved.'}, status=status.HTTP_200_OK)


class CommentApiView(APIView):
    # permission_classes = [IsAuthenticated, IsChallengeCreator | IsOwner]
    # permission_classes = [IsAuthenticated, IsChallengeCreator | IsManager]
    permission_classes = [IsAuthenticated, IsOwner]
    renderer_classes = [ChallengeCreatorRenderer]

    def get(self,  request, pk):
        try:
            query = Comment.objects.filter(post_id = pk).order_by('-created_at')
            print('QUERY == ',query)
            serializer = ListCommentSerializer(query, many=True)
            print('Serializer == ',serializer)
            response={
                'data':serializer.data,
                'status': status.HTTP_200_OK
            }
            return Response(response, status=status.HTTP_200_OK)

        except Comment.DoesNotExist:
            response = {
                'success': False,
                'message': "Post Does not exists.",
                'status': status.HTTP_404_NOT_FOUND,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        try:
            post_id = request.data['post_id']
            try:
                company_name = request.data['company_name']
            except:
                company_name=""

            print('REQUEST DATA =====', company_name)
            serializer = PostCommentSerializer(data= request.data, context = {'user':request.user.id,
                                               'post_id':post_id,'company_name':company_name})

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ChallengeStatement.DoesNotExist:
            response = {
                'success': False,
                'message': "Post Does not exists.",
                'status': status.HTTP_404_NOT_FOUND,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)

















