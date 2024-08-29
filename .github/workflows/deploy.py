import multiprocessing
import os
import re
import statistics
import sys
from collections import defaultdict

import docker
import subprocess
import pathlib
import requests
import json
import typing as tp
import logging
from urllib.parse import urlparse
from python_terraform import Terraform
from paramiko import SSHClient
from scp import SCPClient
try:
    import pandas as pd
except ImportError:
    print("Please install pandas library: 'pip install pandas' and 'pip install tabulate' for requests statistics")

try:
    import click
except ImportError:
    print("Please install click library: pip install click==8.0.3")
    sys.exit(1)


@click.group()
def cli():
    pass


ERR_MSG_TPL = {
    "blocks": [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": ""},
        },
        {"type": "divider"},
    ]
}

DOCKER_USERNAME = os.environ.get("DOCKER_USERNAME")
DOCKER_PASSWORD = os.environ.get("DOCKER_PASSWORD")
DOCKERHUB_ORG_NAME = os.environ.get("DOCKERHUB_ORG_NAME")

NEON_TEST_RUN_LINK = os.environ.get("NEON_TEST_RUN_LINK")

TFSTATE_BUCKET = os.environ.get("TFSTATE_BUCKET")
TFSTATE_KEY_PREFIX = os.environ.get("TFSTATE_KEY_PREFIX")
TFSTATE_REGION = os.environ.get("TFSTATE_REGION")
IMAGE_NAME = os.environ.get("IMAGE_NAME")

FAUCET_COMMIT = os.environ.get("FAUCET_COMMIT")

NEON_TESTS_IMAGE = os.environ.get("NEON_TESTS_IMAGE")

GH_ORG_NAME = os.environ.get("GH_ORG_NAME")

CONTAINERS = ['proxy', 'solana', 'dbcreation', 'faucet', 'gas_tank', 'indexer']

docker_client = docker.APIClient()
terraform = Terraform(working_dir=pathlib.Path(
    __file__).parent / "full_test_suite")
VERSION_BRANCH_TEMPLATE = r"[vt]{1}\d{1,2}\.\d{1,2}\.x.*"
RELEASE_TAG_TEMPLATE = r"[vt]{1}\d{1,2}\.\d{1,2}\.\d{1,2}"

SOLANA_REQUESTS_TITLE = "<summary>Solana Requests Statistics</summary>"


def is_image_exist(image, tag):
    response = requests.get(
        url=f"https://registry.hub.docker.com/v2/repositories/{DOCKERHUB_ORG_NAME}/{image}/tags/{tag}")
    return response.status_code == 200


def ref_to_image_tag(ref):
    return ref.split('/')[-1]


@cli.command(name="specify_image_tags")
@click.option('--git_sha')
@click.option('--git_ref')
@click.option('--git_head_ref')
@click.option('--git_base_ref')
@click.option('--evm_sha_tag')
@click.option('--evm_tag')
@click.option('--default_evm_tag')
@click.option('--default_faucet_tag')
def specify_image_tags(git_sha,
                       git_ref,
                       git_head_ref,
                       git_base_ref,
                       evm_sha_tag,
                       evm_tag,
                       default_evm_tag,
                       default_faucet_tag):

    # proxy_tag
    if "refs/pull" in git_ref:
        proxy_tag = ref_to_image_tag(git_head_ref)
    elif git_ref == "refs/heads/develop":
        proxy_tag = "latest"
    else:
        proxy_tag = ref_to_image_tag(git_ref)

    # proxy_sha_tag
    proxy_sha_tag = git_sha
    if evm_sha_tag:
        proxy_sha_tag = f"{proxy_sha_tag}-{evm_sha_tag[:7]}"

    # proxy_pr_version_branch
    proxy_pr_version_branch = ""
    if git_base_ref:
        if re.match(VERSION_BRANCH_TEMPLATE,  ref_to_image_tag(git_base_ref)) is not None:
            proxy_pr_version_branch = ref_to_image_tag(git_base_ref)

    # is_proxy_release
    if re.match(RELEASE_TAG_TEMPLATE, proxy_tag) is not None:
        is_proxy_release = True
    else:
        is_proxy_release = False

    # evm_tag and evm_sha_tag
    if evm_sha_tag:
        evm_sha_tag = evm_sha_tag
        evm_tag = evm_tag
    else:
        evm_sha_tag = ""
        evm_tag = proxy_tag if is_image_exist("evm_loader", proxy_tag) else default_evm_tag

    # faucet_tag
    faucet_tag = proxy_tag if is_image_exist("neon-faucet", proxy_tag) else default_faucet_tag

    # test_image_tag
    if evm_tag and is_image_exist("neon-tests", evm_tag):
        neon_test_tag = evm_tag
    elif "refs/tags/" in git_ref:
        neon_test_tag = re.sub(r'\.[0-9]*$', '.x', proxy_tag)
        if not is_image_exist("neon-tests", neon_test_tag):
            raise RuntimeError(f"neon-tests image with {neon_test_tag} tag isn't found")
    elif is_image_exist("neon-tests", proxy_tag):
        neon_test_tag = proxy_tag
    elif proxy_pr_version_branch and is_image_exist("neon-tests", proxy_pr_version_branch):
        neon_test_tag = proxy_pr_version_branch
    else:
        neon_test_tag = "latest"

    env = dict(proxy_tag=proxy_tag,
               proxy_sha_tag=proxy_sha_tag,
               proxy_pr_version_branch=proxy_pr_version_branch,
               is_proxy_release=is_proxy_release,
               evm_tag=evm_tag,
               evm_sha_tag=evm_sha_tag,
               faucet_tag=faucet_tag,
               neon_test_tag=neon_test_tag)
    set_github_env(env)


@cli.command(name="build_docker_image")
@click.option('--evm_tag', help="the neon evm_loader image tag that will be used for the build")
@click.option('--proxy_tag', help="a tag to be generated for the proxy image")
@click.option('--skip_pull', is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def build_docker_image(evm_tag,  proxy_tag, skip_pull):
    neon_evm_image = f'{DOCKERHUB_ORG_NAME}/evm_loader:{evm_tag}'

    click.echo(f"evm_loader image: {neon_evm_image}")
    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_client.pull(neon_evm_image, stream=True, decode=True)
        process_output(out)

    else:
        click.echo('skip pulling of docker images')

    buildargs = {"NEON_EVM_COMMIT": evm_tag,
                 "DOCKERHUB_ORG_NAME": DOCKERHUB_ORG_NAME,
                 "PROXY_REVISION": proxy_tag}

    click.echo("Start build")

    output = docker_client.build(
        tag=f"{IMAGE_NAME}:{proxy_tag}", buildargs=buildargs, path="./", decode=True, network_mode='host')
    process_output(output)


@cli.command(name="publish_image")
@click.option('--proxy_sha_tag')
@click.option('--proxy_tag')
def publish_image(proxy_sha_tag, proxy_tag):
    push_image_with_tag(proxy_sha_tag, proxy_sha_tag)
    # push latest and version tags only on the finalizing step
    if proxy_tag != "latest" and re.match(RELEASE_TAG_TEMPLATE, proxy_tag) is None:
        push_image_with_tag(proxy_sha_tag, proxy_tag)


def push_image_with_tag(sha, tag):
    click.echo(f"The tag for publishing: {tag}")
    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    docker_client.tag(f"{IMAGE_NAME}:{sha}", f"{IMAGE_NAME}:{tag}")
    out = docker_client.push(f"{IMAGE_NAME}:{tag}", decode=True, stream=True)
    process_output(out)


@cli.command(name="finalize_image")
@click.option('--proxy_sha_tag')
@click.option('--proxy_tag')
def finalize_image(proxy_sha_tag, proxy_tag):
    if re.match(RELEASE_TAG_TEMPLATE, proxy_tag) is not None or proxy_tag == "latest":
        push_image_with_tag(proxy_sha_tag, proxy_tag)
    else:
        click.echo(f"Nothing to finalize, the tag {proxy_tag} is not version tag or latest")


@cli.command(name="terraform_infrastructure")
@click.option('--proxy_tag')
@click.option('--evm_tag')
@click.option('--faucet_tag')
@click.option('--run_number')
def terraform_build_infrastructure(proxy_tag, evm_tag, faucet_tag, run_number):
    os.environ["TF_VAR_proxy_image_tag"] = proxy_tag
    os.environ["TF_VAR_neon_evm_commit"] = evm_tag
    os.environ["TF_VAR_faucet_model_commit"] = faucet_tag
    os.environ["TF_VAR_dockerhub_org_name"] = DOCKERHUB_ORG_NAME
    os.environ["TF_VAR_proxy_image_name"] = "neon-proxy.py"

    thstate_key = f'{TFSTATE_KEY_PREFIX}{proxy_tag}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    return_code, stdout, stderr = terraform.init(backend_config=backend_config)
    if return_code != 0:
        print("Terraform init failed:", stderr)
    return_code, stdout, stderr = terraform.apply(skip_plan=True, capture_output=False)
    click.echo(f"stdout: {stdout}")
    with open(f"terraform.log", "w") as file:
        if stdout:
            file.write(stdout)
        if stderr:
            file.write(stderr)
    if return_code != 0:
        print("Terraform apply failed:", stderr)
        print("Terraform infrastructure is not built correctly")
        sys.exit(1)
    output = terraform.output(json=True)
    click.echo(f"output: {output}")
    proxy_ip = output["proxy_ip"]["value"]
    solana_ip = output["solana_ip"]["value"]
    infra = dict(solana_ip=solana_ip, proxy_ip=proxy_ip)
    set_github_env(infra)


def set_github_env(envs: tp.Dict, upper=True) -> None:
    """Set environment for github action"""
    path = os.getenv("GITHUB_ENV", str())
    if os.path.exists(path):
        print(f"Set environment variables: {envs}")
        with open(path, "a") as env_file:
            for key, value in envs.items():
                env_file.write(f"\n{key.upper() if upper else key}={str(value)}")


@cli.command(name="destroy_terraform")
@click.option('--proxy_tag')
@click.option('--run_number')
def destroy_terraform(proxy_tag, run_number):
    log = logging.getLogger()
    log.handlers = []
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)4s %(name)4s [%(filename)s:%(lineno)s - %(funcName)s()] %(levelname)4s %(message)4s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    os.environ["TF_VAR_dockerhub_org_name"] = DOCKERHUB_ORG_NAME
    os.environ["TF_VAR_proxy_image_name"] = "neon-proxy.py"

    def format_tf_output(output):
        return re.sub(r'(?m)^', ' ' * TF_OUTPUT_OFFSET, str(output))

    TF_OUTPUT_OFFSET = 16
    os.environ["TF_VAR_proxy_image_tag"] = proxy_tag
    thstate_key = f'{TFSTATE_KEY_PREFIX}{proxy_tag}-{run_number}'

    backend_config = {"bucket": TFSTATE_BUCKET,
                      "key": thstate_key, "region": TFSTATE_REGION}
    terraform.init(backend_config=backend_config)
    tf_destroy = terraform.apply('-destroy', skip_plan=True)
    log.info(format_tf_output(tf_destroy))


@cli.command(name="get_container_logs")
def get_all_containers_logs():
    home_path = os.environ.get("HOME")
    artifact_logs = "./logs"
    ssh_key = f"{home_path}/.ssh/ci-stands"
    os.mkdir(artifact_logs)
    proxy_ip = os.environ.get("PROXY_IP")
    solana_ip = os.environ.get("SOLANA_IP")

    subprocess.run(
        f'ssh-keygen -R {solana_ip} -f {home_path}/.ssh/known_hosts', shell=True)
    subprocess.run(
        f'ssh-keygen -R {proxy_ip} -f {home_path}/.ssh/known_hosts', shell=True)
    subprocess.run(
        f'ssh-keyscan -H {solana_ip} >> {home_path}/.ssh/known_hosts', shell=True)
    subprocess.run(
        f'ssh-keyscan -H {proxy_ip} >> {home_path}/.ssh/known_hosts', shell=True)
    ssh_client = SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.connect(hostname=solana_ip, username='root',
                       key_filename=ssh_key, timeout=120)

    upload_remote_logs(ssh_client, "tmp_solana_1", artifact_logs)

    ssh_client.connect(hostname=proxy_ip, username='root',
                       key_filename=ssh_key, timeout=120)
    services = ["postgres", "dbcreation", "indexer", "proxy", "faucet"]
    for service in services:
        upload_remote_logs(ssh_client, service, artifact_logs)


def upload_remote_logs(ssh_client, service, artifact_logs):
    scp_client = SCPClient(transport=ssh_client.get_transport())
    click.echo(f"Upload logs for service: {service}")
    ssh_client.exec_command(f"touch /tmp/{service}.log.bz2")
    stdin, stdout, stderr = ssh_client.exec_command(
        f'sudo docker logs {service} 2>&1 | pbzip2 -f > /tmp/{service}.log.bz2')
    print(stdout.read())
    print(stderr.read())
    stdin, stdout, stderr = ssh_client.exec_command(f'ls -lh /tmp/{service}.log.bz2')
    print(stdout.read())
    print(stderr.read())
    scp_client.get(f'/tmp/{service}.log.bz2', artifact_logs)


@cli.command(name="deploy_check")
@click.option("--proxy_tag", help="the neon proxy image tag")
@click.option("--test_files", help="comma-separated file names if you want to run a specific list of tests")
@click.option("--mount_local", is_flag=True, default=False, help="mount local dir to the docker")
@click.option("--skip_pull", is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def deploy_check(proxy_tag, test_files, mount_local, skip_pull):
    neon_proxy_image = f"{IMAGE_NAME}:{proxy_tag}"
    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_client.pull(neon_proxy_image, stream=True, decode=True)
        process_output(out)

    host_cfg = None
    volume_list = None
    if mount_local:
        l1_path, _ = os.path.split(__file__)
        l2_path, _ = os.path.split(l1_path)
        l3_path, _ = os.path.split(l2_path)

        dir_list = ["common", "tests"]
        volume_list = [os.path.join(l3_path, d) for d in dir_list]
        bind_dict = {
            os.path.join(l3_path, d): {"bind": os.path.join("/opt/neon-proxy", d), "mode": "rw"} for d in dir_list
        }
        host_cfg = docker_client.create_host_config(binds=bind_dict)

    cont = docker_client.create_container(
        f"{IMAGE_NAME}:{proxy_tag}",
        volumes=volume_list,
        host_config=host_cfg,
        detach=True,
        entrypoint="tail -f /dev/null",
    )
    cont_id = cont["Id"]
    try:
        click.echo(f"Start container {cont_id}")
        docker_client.start(cont_id)

        test_list = get_test_list(cont_id)
        if test_files is not None:
            test_file_list = test_files.split(",")
            test_list = [(d, f) for d, f in test_list if f in test_file_list]

        with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
            err_cnt_list = p.starmap(run_test, [(cont_id, d, f) for d, f in test_list])
    finally:
        docker_client.stop(cont_id, timeout=0)
        docker_client.remove_container(cont_id, force=True)

    err_cnt = sum(err_cnt_list)
    if err_cnt > 0:
        raise RuntimeError(f"Tests failed! Errors count: {err_cnt}")


def get_test_list(cont_id: str) -> tp.List[tp.Tuple[str, str]]:
    inst = docker_client.exec_create(cont_id, 'find tests/ -type f -name "test_*.py" -printf "%p\n"')
    inst_id = inst["Id"]
    click.echo(f"Exec {inst_id}")
    out = docker_client.exec_start(inst_id)
    test_list = out.decode("utf-8").strip().split("\n")
    return [(os.path.dirname(p), os.path.basename(p)) for p in test_list]


def run_test(cont_id, dir_name, file_name):
    # it is a fake configuration, which isn't used in a test,
    #  but it allows to skip validation step of the Config object
    local_env = {
        "EVM_LOADER": "53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io",
        "SOLANA_URL": "https://solana:8899",
        "POSTGRES_DB": "neon-db",
        "POSTGRES_USER": "neon-proxy",
        "POSTGRES_PASSWORD": "neon-proxy-pass",
        "POSTGRES_HOST": "postgres",
    }
    # not fake
    local_docker_cli = docker.APIClient()
    inst = local_docker_cli.exec_create(
        cont_id,
        ["./tests/deploy-test.sh", dir_name, file_name],
        environment=local_env,
    )

    inst_id = inst["Id"]
    click.echo(f"Running {file_name} tests in {inst_id}")
    test_out, test_logs = local_docker_cli.exec_start(inst_id, demux=True)
    test_logs = test_logs.decode("utf-8")
    click.echo(test_out)
    click.echo(test_logs)
    err_cnt = 0
    for line in test_logs.split("\n"):
        if re.match(r"FAILED \(.+=\d+", line):
            err_cnt += int(re.search(r"\d+", line).group(0))
    return err_cnt


@cli.command(name="send_notification", help="Send notification to slack")
@click.option("-u", "--url", help="slack app endpoint url.")
@click.option("-b", "--build_url", help="github action test build url.")
def send_notification(url, build_url):
    tpl = ERR_MSG_TPL.copy()

    parsed_build_url = urlparse(build_url).path.split("/")
    build_id = parsed_build_url[-1]
    repo_name = f"{parsed_build_url[1]}/{parsed_build_url[2]}"

    tpl["blocks"][0]["text"]["text"] = (
        f"*Build <{build_url}|`{build_id}`> of repository `{repo_name}` is failed.*"
        f"\n<{build_url}|View build details>"
    )
    requests.post(url=url, data=json.dumps(tpl))


def process_output(output):
    for line in output:
        if line:
            errors = set()
            try:
                if "status" in line:
                    click.echo(line["status"])

                elif "stream" in line:
                    stream = re.sub("^\n", "", line["stream"])
                    stream = re.sub("\n$", "", stream)
                    stream = re.sub("\n(\x1B\\[0m)$", "\\1", stream)
                    if stream:
                        click.echo(stream)

                elif "aux" in line:
                    if "Digest" in line["aux"]:
                        click.echo("digest: {}".format(line["aux"]["Digest"]))

                    if "ID" in line["aux"]:
                        click.echo("ID: {}".format(line["aux"]["ID"]))

                else:
                    click.echo("not recognized (1): {}".format(line))

                if "error" in line:
                    errors.add(line["error"])

                if "errorDetail" in line:
                    errors.add(line["errorDetail"]["message"])

                    if "code" in line:
                        error_code = line["errorDetail"]["code"]
                        errors.add("Error code: {}".format(error_code))

            except ValueError as e:
                click.echo("not recognized (2): {}".format(line))

            if errors:
                message = "problem executing Docker: {}".format(". ".join(errors))
                raise SystemError(message)


# Regular expression to match the log format
log_pattern = re.compile(r"{.*}")


def extract_method(request_body):
    try:
        request_json = json.loads(request_body)
        return request_json.get("method", "unknown")
    except json.JSONDecodeError:
        return "unknown"


def parse_log_file(log_file_path) -> dict:
    # Read and parse the log file
    stats = defaultdict(lambda: {"times": list()})

    lines = (line for line in log_file_path.split("\n") if log_pattern.match(line))
    log_entries = (json.loads(line) for line in lines)
    formated_requests = (
        {
            "request_time": float(log_entry.get("request_time", 0)),
            "method": extract_method(log_entry.get("jsonrpc_method", "")),
        }
        for log_entry in log_entries if extract_method(log_entry.get("jsonrpc_method", "")) != "unknown"
    )
    for formated_request in formated_requests:
        method = formated_request["method"]
        stats[method]["times"].append(formated_request["request_time"])
    return stats


def calculate_stats(stats):
    formated_stats = {key: {} for key in stats.keys()}
    for method, data in stats.items():
        formated_stats[method]["count"] = len(data["times"])
        formated_stats[method]["average_time"] = statistics.mean(data["times"])
        formated_stats[method]["max_time"] = max(data["times"])
        formated_stats[method]["min_time"] = min(data["times"])
        formated_stats[method]["median_time"] = statistics.median(data["times"])
    return {k: v for k, v in sorted(formated_stats.items(), key=lambda item: item[1]["count"], reverse=True)}


@cli.command("parse_logs", help="Get logs from nginx")
@click.option("--solana_ip", default="localhost", help="Solana IP")
def parse_logs(solana_ip):
    try:
        content = requests.get(f"http://{solana_ip}:8080/logs/access.log").text
    except requests.exceptions.InvalidURL as e:
        print(f"Error: {e}")
        sys.exit(1)
    stats = parse_log_file(content)
    calculated_stats = calculate_stats(stats)
    df = pd.DataFrame.from_dict(calculated_stats, orient="index", columns=["count", "min_time", "max_time", "average_time", "median_time"])
    print(df.to_markdown())


class GithubClient:

    def __init__(self, token):
        self.headers = {"Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def remove_comment_with_title(self, pull_request, title):
        try:
            response = requests.get(pull_request, headers=self.headers)
        except requests.exceptions.MissingSchema as e:
            click.echo(f"Ignoring PR: {pull_request}. Error: {e}.")
        else:
            if response.status_code != 200:
                raise RuntimeError(f"Attempt to get comments on a PR failed: {response.text}")
            comments = response.json()
            for comment in comments:
                if f"<details>{title}" in comment["body"]:
                    response = requests.delete(comment["url"], headers=self.headers)
                    if response.status_code != 204:
                        raise RuntimeError(f"Attempt to delete a comment on a {response.request.url} failed: {response.text}")

    def add_comment_to_pr(self, msg, pull_request, title = SOLANA_REQUESTS_TITLE, remove_previous_comments=True):
        if remove_previous_comments:
            self.remove_comment_with_title(pull_request, title)
        message = f"\n\n{msg}\n\n"
        if title:
            message = f"<details>{title}\n\n{message}</details>"
        data = {"body": message}
        click.echo(f"Sent data: {data}")
        click.echo(f"Headers: {self.headers}")
        try:
            response = requests.post(pull_request, json=data, headers=self.headers)
        except requests.exceptions.MissingSchema as e:
            click.echo(f"Ignoring PR: {pull_request}. Error: {e}.")
        else:
            click.echo(f"Status code: {response.status_code}. Response: {response.text}")
            if response.status_code != 201:
                raise RuntimeError(f"Attempt to leave a comment on a PR failed: {response.text}")            


@cli.command("post_comment", help="Post comment to the PR")
@click.option("--message", help="Message to post")
@click.option("--pull_request", help="Pull Request URL")
@click.option("--token", help="Github token")
def post_comment(message, pull_request, token):
    gh_client = GithubClient(token)
    gh_client.add_comment_to_pr(message, pull_request)


if __name__ == "__main__":
    cli()
