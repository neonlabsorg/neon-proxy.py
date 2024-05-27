import multiprocessing
import os
import re
import time
import sys

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


def docker_compose(args: str):
    command = f'docker login -u {DOCKER_USERNAME} -p {DOCKER_PASSWORD}'
    click.echo(f"run command: {command}")
    out = subprocess.run(command, shell=True)
    click.echo("return code: " + str(out.returncode))

    command = f'docker-compose --compatibility {args}'
    click.echo(f"run command: {command}")
    out = subprocess.run(command, shell=True)
    click.echo("return code: " + str(out.returncode))
    if out.returncode != 0:
        raise RuntimeError(f"Command {command} failed. Err: {out.stderr}")

    return out


def check_neon_evm_tag(tag):
    response = requests.get(
        url=f"https://registry.hub.docker.com/v2/repositories/{DOCKERHUB_ORG_NAME}/evm_loader/tags/{tag}")
    if response.status_code != 200:
        raise RuntimeError(
            f"evm_loader image with {tag} tag isn't found. Response: {response.json()}")


def is_branch_exist(branch, repo):
    if branch:
        response = requests.get(f"https://api.github.com/repos/{GH_ORG_NAME}/{repo}/branches/{branch}")
        if response.status_code == 200:
            click.echo(f"The branch {branch} exist in the {repo} repository")
            return True
    else:
        return False


def update_neon_evm_tag_if_same_branch_exists(branch, neon_evm_tag):
    if is_branch_exist(branch, "neon-evm"):
        neon_evm_tag = branch.split('/')[-1]
        check_neon_evm_tag(neon_evm_tag)
    return neon_evm_tag

def update_faucet_tag_if_same_branch_exists(branch, faucet_tag):
    if is_branch_exist(branch, "neon-faucet"):
        faucet_tag = branch.split('/')[-1]
    print(f"faucet image tag: {faucet_tag}")
    return faucet_tag


@cli.command(name="build_docker_image")
@click.option('--neon_evm_tag', help="the neon evm_loader image tag that will be used for the build")
@click.option('--proxy_tag', help="a tag to be generated for the proxy image")
@click.option('--head_ref_branch')
@click.option('--skip_pull', is_flag=True, default=False, help="skip pulling of docker images from the docker-hub")
def build_docker_image(neon_evm_tag,  proxy_tag, head_ref_branch, skip_pull):
    neon_evm_tag = update_neon_evm_tag_if_same_branch_exists(head_ref_branch, neon_evm_tag)
    neon_evm_image = f'{DOCKERHUB_ORG_NAME}/evm_loader:{neon_evm_tag}'

    click.echo(f"neon-evm image: {neon_evm_image}")
    if not skip_pull:
        click.echo('pull docker images...')
        out = docker_client.pull(neon_evm_image, stream=True, decode=True)
        process_output(out)

    else:
        click.echo('skip pulling of docker images')

    buildargs = {"NEON_EVM_COMMIT": neon_evm_tag,
                 "DOCKERHUB_ORG_NAME": DOCKERHUB_ORG_NAME,
                 "PROXY_REVISION": proxy_tag}

    click.echo("Start build")

    output = docker_client.build(
        tag=f"{IMAGE_NAME}:{proxy_tag}", buildargs=buildargs, path="./", decode=True, network_mode='host')
    process_output(output)


@cli.command(name="publish_image")
@click.option('--proxy_tag')
@click.option('--head_ref')
@click.option('--github_ref_name')
def publish_image(proxy_tag, head_ref, github_ref_name):
    push_image_with_tag(proxy_tag, proxy_tag)
    branch_name_tag = None
    if head_ref:
        branch_name_tag = head_ref.split('/')[-1]
    elif re.match(VERSION_BRANCH_TEMPLATE,  github_ref_name):
        branch_name_tag = github_ref_name
    if branch_name_tag:
        push_image_with_tag(proxy_tag, branch_name_tag)


def push_image_with_tag(sha, tag):
    click.echo(f"The tag for publishing: {tag}")
    docker_client.login(username=DOCKER_USERNAME, password=DOCKER_PASSWORD)
    docker_client.tag(f"{IMAGE_NAME}:{sha}", f"{IMAGE_NAME}:{tag}")
    out = docker_client.push(f"{IMAGE_NAME}:{tag}", decode=True, stream=True)
    process_output(out)

@cli.command(name="finalize_image")
@click.option('--github_ref')
@click.option('--proxy_tag')
def finalize_image(github_ref, proxy_tag):
    final_tag = ""
    if 'refs/tags/' in github_ref:
        final_tag = github_ref.replace("refs/tags/", "")
    elif github_ref == 'refs/heads/develop':
        final_tag = 'latest'

    if final_tag:
        out = docker_client.pull(f"{IMAGE_NAME}:{proxy_tag}", decode=True, stream=True)
        process_output(out)
        push_image_with_tag(proxy_tag, final_tag)
    else:
        click.echo(f"Nothing to finalize, github_ref {github_ref} is not a tag or develop ref")


@cli.command(name="terraform_infrastructure")
@click.option('--head_ref_branch')
@click.option('--github_ref_name')
@click.option('--proxy_tag')
@click.option('--neon_evm_tag')
@click.option('--faucet_tag')
@click.option('--run_number')
def terraform_build_infrastructure(head_ref_branch, github_ref_name, proxy_tag, neon_evm_tag, faucet_tag, run_number):
    branch = head_ref_branch if head_ref_branch != "" else github_ref_name
    neon_evm_tag = update_neon_evm_tag_if_same_branch_exists(head_ref_branch, neon_evm_tag)
    if branch not in ['master', 'develop']:
        faucet_tag = update_faucet_tag_if_same_branch_exists(branch, faucet_tag)
    os.environ["TF_VAR_branch"] = branch.replace('_', '-')
    os.environ["TF_VAR_proxy_image_tag"] = proxy_tag
    os.environ["TF_VAR_neon_evm_commit"] = neon_evm_tag
    os.environ["TF_VAR_faucet_model_commit"] = faucet_tag
    os.environ["TF_VAR_dockerhub_org_name"] = DOCKERHUB_ORG_NAME
    os.environ["TF_VAR_proxy_image_name"] = "neon-proxy.py"
    os.environ["TF_VAR_docker_username"] = DOCKER_USERNAME
    os.environ["TF_VAR_docker_password"] = DOCKER_PASSWORD

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
    os.environ["TF_VAR_docker_username"] = DOCKER_USERNAME
    os.environ["TF_VAR_docker_password"] = DOCKER_PASSWORD
    
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
    #  but it allows to ckip validation step of the Config object
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
                    stream = re.sub("\n(\x1B\[0m)$", "\\1", stream)
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


if __name__ == "__main__":
    cli()
