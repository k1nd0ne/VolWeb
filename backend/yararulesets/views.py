from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from django.conf import settings
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.core.files.storage import default_storage
from django.db.utils import IntegrityError
from .models import YaraRuleSet, UploadSession
from yararules.models import YaraRule
from .serializers import YaraRuleSetSerializer, InitiateUploadSerializer, UploadChunkSerializer, CompleteUploadSerializer
from yararules.serializers import YaraRuleSerializer
from yararules.utils import BatchUploadManager, compute_content_hash, get_existing_content_hashes
from core.validators import safe_media_path
import os
import shutil
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import tempfile
import requests
import zipfile
from django.db import transaction
import re
from urllib.parse import urlparse
import uuid
import logging
import hashlib
from django.http import HttpResponse

logger = logging.getLogger(__name__)


class YaraRuleSetViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = YaraRuleSet.objects.all()
    serializer_class = YaraRuleSetSerializer

    def create(self, request, *args, **kwargs):
        name = request.data.get("name")
        description = request.data.get("description")
        is_default = request.data.get("is_default", False)

        try:
            yara_ruleset = YaraRuleSet(
                name=name, 
                description=description,
                is_default=is_default
            )

            yara_ruleset.save()

            serializer = YaraRuleSetSerializer(yara_ruleset)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except IntegrityError:
            return Response(status=status.HTTP_409_CONFLICT)
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """
        Download all rules in a ruleset as a single .yar file
        """
        try:
            ruleset = self.get_object()
            rules = YaraRule.objects.filter(linked_yararuleset=ruleset)
            
            if not rules.exists():
                return Response(
                    {'error': 'No rules found in this ruleset'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Combine all rules into one file
            content = f"// YARA Ruleset: {ruleset.name}\n"
            content += f"// Description: {ruleset.description}\n"
            content += f"// Total Rules: {rules.count()}\n"
            content += f"// Generated: {ruleset.updated_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            for rule in rules:
                content += f"// Rule: {rule.name}\n"
                if rule.description:
                    content += f"// Description: {rule.description}\n"
                content += rule.rule_content
                content += "\n\n"
            
            # Create the response
            response = HttpResponse(content, content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{ruleset.name}.yar"'
            
            return response
            
        except Exception as e:
            return Response(
                {'error': f'Failed to download ruleset: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class InitiateUploadView(APIView):
    permission_classes = [IsAuthenticated]  
    def post(self, request):
        serializer = InitiateUploadSerializer(data=request.data)
        if serializer.is_valid():
            filename = serializer.validated_data['filename']
            yara_ruleset_id = serializer.validated_data.get('yara_ruleset_id')
            description = serializer.validated_data.get('description', '')
            source = serializer.validated_data.get('source', 'uploaded')

            yara_ruleset = None
            if yara_ruleset_id:
                try:
                    yara_ruleset = YaraRuleSet.objects.get(id=yara_ruleset_id)
                except YaraRuleSet.DoesNotExist:
                    return Response({
                        'error': 'Invalid ruleset ID'
                    }, status=status.HTTP_400_BAD_REQUEST)

            upload_session = UploadSession.objects.create(
                filename=filename,
                yararuleset=yara_ruleset,
                description=description,
                source=source
            )

            # Create a temporary directory for the upload session
            upload_id = str(upload_session.upload_id)
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', upload_id)
            os.makedirs(temp_dir, exist_ok=True)

            return Response({'upload_id': upload_id}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UploadChunkView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UploadChunkSerializer(data=request.data)
        if serializer.is_valid():
            upload_id = serializer.validated_data['upload_id']
            part_number = serializer.validated_data['part_number']
            chunk = serializer.validated_data['chunk']

            try:
                UploadSession.objects.get(upload_id=upload_id)
            except UploadSession.DoesNotExist:
                return Response({'error': 'Invalid upload_id'}, status=status.HTTP_400_BAD_REQUEST)

            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', str(upload_id))
            if not os.path.exists(temp_dir):
                return Response({'error': 'Upload session has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            chunk_filename = f'chunk_{part_number}'
            chunk_path = os.path.join(temp_dir, chunk_filename)

            with open(chunk_path, 'wb') as f:
                for chunk_data in chunk.chunks():
                    f.write(chunk_data)

            return Response({'status': 'chunk uploaded'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CompleteUploadView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = CompleteUploadSerializer(data=request.data)
        if serializer.is_valid():
            upload_id = serializer.validated_data['upload_id']

            try:
                upload_session = UploadSession.objects.get(upload_id=upload_id)
            except UploadSession.DoesNotExist:
                return Response({'error': 'Invalid upload_id.'}, status=status.HTTP_400_BAD_REQUEST)

            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_uploads', str(upload_id))

            if not os.path.exists(temp_dir):
                return Response({'error': 'Upload session has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            chunk_files = os.listdir(temp_dir)
            try:
                chunk_files.sort(key=lambda x: int(x.split('_')[1]))
            except ValueError:
                return Response({'error': 'Invalid chunk filenames.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                final_file_path = safe_media_path('yara_files', upload_session.filename)
            except ValueError:
                return Response({'error': 'Invalid filename.'}, status=status.HTTP_400_BAD_REQUEST)
            os.makedirs(os.path.dirname(final_file_path), exist_ok=True)

            # Assemble the chunks into the final file
            with open(final_file_path, 'wb') as final_file:
                for chunk_file in chunk_files:
                    chunk_path = os.path.join(temp_dir, chunk_file)
                    with open(chunk_path, 'rb') as chunk:
                        shutil.copyfileobj(chunk, final_file)

            # Clean up temporary files and directory
            shutil.rmtree(temp_dir)

            # Now process the uploaded file with batch optimization
            try:
                created_rules, skipped_duplicates = self._process_uploaded_file_with_batch(
                    final_file_path,
                    upload_session.yararuleset,
                    upload_session.description,
                    upload_session.source
                )

                # Clean up the temporary file
                os.remove(final_file_path)

                # Delete the upload session
                upload_session.delete()

                # Send WebSocket notification for all created rules
                channel_layer = get_channel_layer()
                for rule in created_rules:
                    async_to_sync(channel_layer.group_send)(
                        "yararules",
                        {
                            "type": "send_notification",
                            "status": "created",
                            "message": YaraRuleSerializer(rule).data
                        }
                    )

                return Response({
                    'status': 'upload complete',
                    'rules_created': len(created_rules),
                    'skipped_duplicates': skipped_duplicates,
                    'rules': YaraRuleSerializer(created_rules, many=True).data
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"File processing failed: {str(e)}")
                # Clean up the temporary file on error
                if os.path.exists(final_file_path):
                    os.remove(final_file_path)
                upload_session.delete()
                return Response({
                    'error': f'File processing failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _process_uploaded_file_with_batch(self, file_path, yara_ruleset, description, source):
        """
        Process uploaded YARA file with batch upload optimization.
        
        This method uses the BatchUploadManager to:
        1. Disable automatic ruleset validation during rule creation
        2. Create all rules efficiently  
        3. Trigger a single ruleset validation at the end
        """
        logger.info(f"Starting optimized file processing for {file_path}")
        
        # Import the BatchUploadManager
        from yararules.utils import BatchUploadManager
        
        # Create batch upload manager
        batch_manager = BatchUploadManager(
            ruleset_id=yara_ruleset.id if yara_ruleset else None
        )

        created_rules = []
        skipped_duplicates = 0
        # Skip rules whose content already exists in the DB or earlier in this batch.
        seen_hashes = get_existing_content_hashes()

        with batch_manager.batch_context():
            # Read the file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if it's a single rule or multiple rules
            if self._is_single_rule_file(content):
                # Single rule file
                rule = self._create_rule_from_content(
                    content,
                    yara_ruleset,
                    description,
                    source,
                    os.path.basename(file_path),
                    seen_hashes
                )
                if rule:
                    batch_manager.add_created_rule(rule)
                    created_rules.append(rule)
                    logger.debug(f"Created single rule {rule.name}")
                else:
                    skipped_duplicates += 1
            else:
                # Multiple rules in one file - split them
                individual_rules = self._split_yara_rules(content)

                for i, rule_content in enumerate(individual_rules):
                    if rule_content.strip():
                        try:
                            rule = self._create_rule_from_content(
                                rule_content,
                                yara_ruleset,
                                description,
                                source,
                                f"{os.path.basename(file_path)}_rule_{i+1}",
                                seen_hashes
                            )
                            if rule:
                                batch_manager.add_created_rule(rule)
                                created_rules.append(rule)
                                logger.debug(f"Created rule {rule.name} ({i+1}/{len(individual_rules)})")
                            else:
                                skipped_duplicates += 1

                        except Exception as e:
                            logger.error(f"Failed to create rule {i+1}: {e}")
                            continue

        # At this point, we're outside the batch context
        # The BatchUploadManager automatically triggered ruleset validation

        logger.info(
            f"Successfully processed {batch_manager.get_created_count()} rules from "
            f"uploaded file ({skipped_duplicates} duplicate(s) skipped)"
        )
        return created_rules, skipped_duplicates

    def _is_single_rule_file(self, content):
        """Check if the file contains a single YARA rule"""
        import re
        rule_matches = re.findall(r'rule\s+\w+', content)
        return len(rule_matches) <= 1

    def _split_yara_rules(self, content):
        """Split content into individual YARA rules"""
        import re
        
        # Find all rule definitions
        rules = []
        pattern = r'(rule\s+\w+.*?(?=rule\s+\w+|$))'
        matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
        
        if matches:
            rules = matches
        else:
            # Fallback: treat as single rule
            rules = [content]
        
        return rules

    def _create_rule_from_content(self, content, yara_ruleset, description, source, filename, seen_hashes):
        """
        Create a YARA rule from content, or return None if it duplicates an
        existing rule. Updates ``seen_hashes`` in place on creation.
        """
        import re
        import hashlib

        content_hash = compute_content_hash(content)
        if content_hash in seen_hashes:
            logger.info(f"Skipping duplicate rule from {filename} (content hash {content_hash[:12]})")
            return None

        # Extract rule name from content
        rule_match = re.search(r'rule\s+(\w+)', content)
        if rule_match:
            rule_name = rule_match.group(1)
        else:
            # Fallback to filename
            rule_name = os.path.splitext(filename)[0]

        # Generate unique etag
        etag_content = f"{rule_name}_{content}_{source}"
        etag = hashlib.md5(etag_content.encode()).hexdigest()

        # Create the rule (this will NOT trigger ruleset validation due to batch context)
        try:
            rule = YaraRule.objects.create(
                name=rule_name,
                etag=etag,
                rule_content=content,
                description=description or f"Uploaded from file: {filename}",
                linked_yararuleset=yara_ruleset,
                source=source,
                is_active=True
            )
        except IntegrityError:
            # An identical rule (same etag) already exists — treat as duplicate.
            logger.info(f"Skipping duplicate rule from {filename} (etag collision)")
            seen_hashes.add(content_hash)
            return None

        seen_hashes.add(content_hash)
        return rule


class GitHubImportView(APIView):
    permission_classes = [IsAuthenticated]
    """
    Import YARA rules from a GitHub repository with batch optimization
    """
    
    def post(self, request):
        github_url = request.data.get('github_url')
        yara_ruleset_id = request.data.get('yara_ruleset_id')
        description = request.data.get('description', '')
        
        if not github_url:
            return Response(
                {'error': 'GitHub URL is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate GitHub URL
        if not self._validate_github_url(github_url):
            return Response(
                {'error': 'Invalid GitHub URL format'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get ruleset if specified
        yara_ruleset = None
        if yara_ruleset_id:
            try:
                yara_ruleset = YaraRuleSet.objects.get(id=yara_ruleset_id)
            except YaraRuleSet.DoesNotExist:
                return Response(
                    {'error': 'Invalid ruleset ID'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        try:
            # Convert GitHub URL to download URL
            download_url = self._convert_to_download_url(github_url)
            
            # Process the repository with batch optimization
            imported_rules, skipped_duplicates = self._process_github_repo_optimized(
                download_url,
                yara_ruleset,
                description
            )

            return Response({
                'success': True,
                'imported_count': len(imported_rules),
                'skipped_duplicates': skipped_duplicates,
                'rules': YaraRuleSerializer(imported_rules, many=True).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"GitHub import failed: {str(e)}")
            return Response(
                {'error': f'Import failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _process_github_repo_optimized(self, download_url, yara_ruleset, description):
        """
        Process GitHub repository with batch upload optimization.
        
        This method uses the BatchUploadManager to:
        1. Disable automatic ruleset validation during rule creation
        2. Create all rules efficiently  
        3. Trigger a single ruleset validation at the end
        """
        logger.info(f"Starting optimized GitHub repo processing for {download_url}")
        
        # Create batch upload manager
        batch_manager = BatchUploadManager(
            ruleset_id=yara_ruleset.id if yara_ruleset else None
        )

        skipped_duplicates = 0
        # Skip rules whose content already exists in the DB or earlier in this batch.
        seen_hashes = get_existing_content_hashes()

        with batch_manager.batch_context():
            imported_rules = []

            with tempfile.TemporaryDirectory() as temp_dir:
                zip_path = os.path.join(temp_dir, 'repo.zip')
                
                # Try main branch first, then master if it fails
                try:
                    self._download_file(download_url, zip_path)
                except requests.HTTPError as e:
                    if e.response.status_code == 404:
                        # Try master branch
                        download_url = download_url.replace('/main.zip', '/master.zip')
                        self._download_file(download_url, zip_path)
                    else:
                        raise
                
                # Extract ZIP
                extract_dir = os.path.join(temp_dir, 'extracted')
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Find and import YARA files
                yara_files = self._find_yara_files(extract_dir)
                
                logger.info(f"Found {len(yara_files)} YARA files to import")
                
                # Create all rules within the batch context
                for i, yara_file in enumerate(yara_files):
                    try:
                        rule = self._import_yara_file_optimized(
                            yara_file,
                            yara_ruleset,
                            description,
                            download_url,
                            seen_hashes
                        )
                        if rule:
                            batch_manager.add_created_rule(rule)
                            imported_rules.append(rule)
                            logger.debug(f"Created rule {rule.name} ({i+1}/{len(yara_files)})")
                        else:
                            skipped_duplicates += 1

                    except Exception as e:
                        logger.error(f"Failed to create rule from {yara_file}: {e}")
                        continue

        # At this point, we're outside the batch context
        # The BatchUploadManager automatically triggered ruleset validation

        logger.info(
            f"Successfully imported {batch_manager.get_created_count()} rules from GitHub "
            f"({skipped_duplicates} duplicate(s) skipped)"
        )
        return imported_rules, skipped_duplicates

    def _import_yara_file_optimized(self, file_path, yara_ruleset, description, source_url, seen_hashes):
        """
        Import a single YARA file, or return None if it duplicates an existing
        rule. Updates ``seen_hashes`` in place on creation.
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        content_hash = compute_content_hash(content)
        if content_hash in seen_hashes:
            logger.info(f"Skipping duplicate rule from {os.path.basename(file_path)} (content hash {content_hash[:12]})")
            return None

        # Extract rule name from file or content
        filename = os.path.basename(file_path)
        rule_name = os.path.splitext(filename)[0]

        # Try to extract rule name from content
        rule_match = re.search(r'rule\s+(\w+)', content)
        if rule_match:
            rule_name = rule_match.group(1)

        # Generate unique etag
        etag = self._generate_etag(rule_name, content, source_url)

        # Create the rule (this will NOT trigger ruleset validation due to batch context)
        try:
            rule = YaraRule.objects.create(
                name=rule_name,
                etag=etag,
                rule_content=content,
                description=description or f"Imported from GitHub: {filename}",
                linked_yararuleset=yara_ruleset,
                source="github",
                url=source_url,
                is_active=True
            )
        except IntegrityError:
            logger.info(f"Skipping duplicate rule from {filename} (etag collision)")
            seen_hashes.add(content_hash)
            return None

        seen_hashes.add(content_hash)
        return rule
    
    def _generate_etag(self, rule_name, rule_content, source_url):
        """Generate unique etag for imported rule"""
        import hashlib
        content = f"{rule_name}_{rule_content}_{source_url}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _validate_github_url(self, url):
        """Validate GitHub URL format"""
        pattern = r'^https?://(www\.)?github\.com/[\w-]+/[\w.-]+/?'
        return bool(re.match(pattern, url))
    
    def _convert_to_download_url(self, github_url):
        """Convert GitHub URL to ZIP download URL"""
        # Remove trailing slash
        github_url = github_url.rstrip('/')
        
        # Parse the URL
        parsed = urlparse(github_url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            raise ValueError("Invalid GitHub repository URL")
        
        owner = path_parts[0]
        repo = path_parts[1]
        
        # Default to main branch, could be enhanced to support specific branches
        return f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
    
    def _download_file(self, url, destination):
        """Download file from URL"""
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def _find_yara_files(self, directory):
        """Recursively find all .yar and .yara files"""
        yara_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    yara_files.append(os.path.join(root, file))
        return yara_files