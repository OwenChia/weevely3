from core import messages
from core.config import agent_templates_folder_path, obfuscators_templates_folder_path
from core.weexceptions import FatalException
from mako.template import Template
import os
import utils


def generate(password, obfuscator='obfusc1_php', agent='obfpost_php'):

    obfuscator_path = os.path.join(obfuscators_templates_folder_path,
                                   obfuscator + '.tpl')
    agent_path = os.path.join(agent_templates_folder_path, agent + '.tpl')

    for path in (obfuscator_path, agent_path):
        if not os.path.isfile(path):
            raise FatalException(messages.generic.file_s_not_found % path)

    obfuscator_template = Template(filename=obfuscator_path)

    try:
        with open(agent_path, 'r') as fd:
            agent = Template(fd.read()).render(password=password)
    except Exception as e:
        raise FatalException(
            messages.generate.error_agent_template_s_s % (agent_path, str(e)))

    minified_agent = utils.code.minify_php(agent)

    # Fallback of vanilla agent if minification went wrong
    agent = minified_agent if minified_agent else agent

    try:
        obfuscated = obfuscator_template.render(agent=agent)
    except Exception as e:
        raise FatalException(messages.generate.error_obfuscator_template_s_s %
                             (obfuscator_path, e))

    return obfuscated


def save_generated(obfuscated, output):

    try:
        with open(output, 'w+') as fd:
            fd.write(obfuscated)
    except Exception as e:
        raise FatalException(
            messages.generic.error_creating_file_s_s % (output, e))
