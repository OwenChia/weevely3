from core.vectors import PhpCode, ModuleExec
from core.module import Module
from core import messages
from core.loggers import log
import random
import hashlib
import base64


class Upload(Module):
    """Upload file to remote filesystem."""

    def init(self):

        self.register_info({'author': ['Emilio Pinna'], 'license': 'GPLv3'})

        self.register_vectors([
            PhpCode(
                "(file_put_contents('${rpath}',base64_decode('${content}'))&&print(1))||print(0);",
                name='file_put_contents'),
            PhpCode(
                """($h=fopen("${rpath}","a+")&&fwrite($h,base64_decode('${content}'))&&fclose($h)&&print(1))||print(0);""",
                name="fwrite")
        ])

        self.register_arguments([
            {
                'name': 'lpath',
                'help': 'Local file path',
                'nargs': '?'
            },
            {
                'name': 'rpath',
                'help': 'Remote file path'
            },
            {
                'name': '-force',
                'help': 'Force overwrite',
                'action': 'store_true',
                'default': False
            },
            {
                'name': '-content',
                'help':
                'Optionally specify the file content'
            },
            {
                'name': '-vector',
                'choices': self.vectors.get_names(),
                'default': 'file_put_contents'
            }
        ])

    def run(self):
        # Load local file
        content_orig = self.args.get('content')
        if content_orig is None:

            lpath = self.args.get('lpath')
            if not lpath:
                log.warning(
                    messages.module_file_upload.error_content_lpath_required)
                return

            try:
                with open(lpath, 'rb') as fd:
                    content_orig = fd.read()
            except Exception as e:
                log.warning(
                    messages.generic.error_loading_file_s_s % (lpath, str(e)))
                return

        if isinstance(content_orig, str):
            content_orig = content_orig.encode()

        self.args['content'] = base64.b64encode(content_orig).decode()

        # Check remote file existence
        if not self.args['force'] and ModuleExec(
                'file_check', [self.args['rpath'], 'exists']).run():
            log.warning(messages.generic.error_file_s_already_exists %
                        self.args['rpath'])
            return

        vector_name, result = self.vectors.find_first_result(
            format_args=self.args,
            condition=lambda result: result == '1')

        if not ModuleExec('file_check', [self.args['rpath'], 'exists']).run():
            log.warning(messages.module_file_upload.failed_upload_file)
            return

        if not (ModuleExec('file_check',
                           [self.args['rpath'], 'md5'
                            ]).run() == hashlib.md5(content_orig).hexdigest()):
            log.warning(messages.module_file_upload.failed_md5_check)
            return

        return True
