## \package Waf.StaticAnalysis.Trivy
## \copydoc Trivy

import textwrap
from typing import List

import waflib

from Waf.Building.Docker.DockerImage import DOCKER_FEATURE_NAME
from Waf.DevelopmentTools.DevelopmentTools import DevelopmentTools
from Waf.Projects.Project import Project
from Waf.Utilities import Filesystem, OpenFileInDefaultProgram, Platform

## Trivy is an open-source vulnerability scanner for detecting security issues in container images, filesystems, and code repositories.
## This code supports using Trivy to scan Docker images built by our build framework and generate HTML vulnerability reports.
## For more information, see the official Trivy documentation: https://github.com/aquasecurity/trivy.
class Trivy(object):
    # CONSTANTS.
    ## The identifying name of the Trivy executable program as a development tool within our Waf build framework.
    DEVELOPMENT_TOOL_NAME: str = 'TRIVY'
    ## The name of the directory to store the vulnerability reports in.
    VULNERABILITY_REPORT_DIRECTORY_NAME: str = 'TrivyVulnerabilityReports'
    ## The name of the directory to use as the cache directory. The cache directory used by Trivy will contain the results
    ## of previous Docker image scans as well as the vulnerability database it automatically downloads from the Internet.
    CACHE_DIRECTORY_NAME: str = 'TrivyCache'

    # STATIC METHODS.
    ## Executes a Trivy scan command and generates a vulnerability report, handling return codes and report opening.
    ## \param[in,out]   build_context - The build context.
    ## \param[in]   trivy_command - The full Trivy command to execute.
    ## \param[in]   scan_target_description - A description of what's being scanned (for error messages).
    ## \param[in]   vulnerability_report - The node representing the output vulnerability report.
    ## \param[in]   vulnerabilities_found_exit_code - The exit code that indicates vulnerabilities were found.
    ## \return  A message indicating the scan result.
    @staticmethod
    def GenerateTrivyVulnerabilityReport(
        build_context: waflib.Build.BuildContext,
        trivy_command: List[str],
        scan_target_description: str,
        vulnerability_report: waflib.Node.Node,
        vulnerabilities_found_exit_code: int) -> str:
        # EXECUTE THE TRIVY SCAN COMMAND.
        exit_code: int = build_context.exec_command(trivy_command)

        # CONSTRUCT THE APPROPRIATE MESSAGE BASED ON THE RETURN CODE.
        SUCCESS_EXIT_CODE: int = 0
        vulnerability_report_filepath: str = vulnerability_report.abspath()
        vulnerability_scan_result_message: str = ''
        vulnerability_scan_succeeded: bool = SUCCESS_EXIT_CODE == exit_code
        if vulnerability_scan_succeeded:
            # INDICATE THAT NO VULNERABILITIES WERE FOUND.
            vulnerability_scan_result_message = textwrap.dedent(f'''
                No vulnerabilities were found in the vulnerability scan.
                The vulnerability report can be found at {vulnerability_report_filepath}.''')
        else:
            # CHECK IF VULNERABILITIES WERE FOUND IN THE REPORT.
            vulnerabilities_found: bool = (vulnerabilities_found_exit_code == exit_code)
            if vulnerabilities_found:
                # INDICATE THAT VULNERABILITIES WERE FOUND IN THE SCAN.
                vulnerability_scan_result_message = textwrap.dedent(f'''
                    Vulnerabilities were found in the vulnerability scan.
                    The vulnerability report can be found at {vulnerability_report_filepath}.''')
            else:
                # INDICATE AN ERROR HAS OCCURRED.
                # The trivy command is expected to return 0 or the value specified by the '--exit-code' command line option
                # in the event that the scan is successful. Any other return code should be treated as an error.
                vulnerability_scan_result_message = f'An error occurred while scanning {scan_target_description}. Return code: {exit_code}.'

        # OPEN THE VULNERABILITY REPORT, IF REQUESTED.
        vulnerability_report_exists: bool = vulnerability_report.exists()
        open_generated_files: bool = build_context.options.open
        open_vulnerability_report: bool = (vulnerability_report_exists and open_generated_files)
        if open_vulnerability_report:
            OpenFileInDefaultProgram(vulnerability_report_filepath)

        return vulnerability_scan_result_message

    ## Deletes the Trivy cache directory. This method is useful to use when cleaning up the workspace.
    ## \param[in,out]  bld - The build context.
    @staticmethod
    def DeleteCacheDirectory(bld: waflib.Build.BuildContext):
        # DELETE THE TRIVY CACHE DIRECTORY.
        trivy_cache_directory: waflib.Node.Node = bld.bldnode.make_node(Trivy.CACHE_DIRECTORY_NAME)
        Filesystem.Path.DeleteAndWarnAboutFailures(trivy_cache_directory)

    ## Clears previously scanned images from the cache to ensure that a new scan is run when the same image is scanned.
    ## \param[in]   trivy_cache_directory - The Trivy cache directory.
    ## \param[in,out]   bld - The build context.
    @staticmethod
    def ClearContainerImageCacheResults(trivy_cache_directory: waflib.Node.Node, bld: waflib.Build.BuildContext):
        # CLEAR THE TRIVY CACHE.
        # It is necessary in order to ensure that a scan is actually done when the same Docker image is scanned again.
        # Trivy will not re-scan a Docker image if it has already scanned the image once before, even if it was updated since the last scan.
        # Trivy will just return the results of the previous scan if the cache is not cleared. Thus, the cache must be cleared to ensure
        # that a new vulnerability report is created whenever a Docker image is scanned.
        trivy_filepath: str = DevelopmentTools.GetPath(bld.env, Trivy.DEVELOPMENT_TOOL_NAME)
        trivy_clear_cache_command: List[str] = [
            trivy_filepath,
            f'--cache-dir={trivy_cache_directory}',
            'clean',
            # Trivy requires specifying exactly what we wish to clean. Here, we just want to clean the scan cache.
            '--scan-cache']
        bld.exec_command(trivy_clear_cache_command)

    ## Creates the vulnerability report directory.
    ## \param[in,out]   bld - The build context.
    ## \return  The vulnerability report directory.
    @staticmethod
    def CreateVulnerabilityReportDirectory(bld: waflib.Build.BuildContext) -> waflib.Node.Node:
        # CREATE THE VULNERABILITY REPORT DIRECTORY.
        vulnerability_report_directory: waflib.Node.Node = bld.bldnode.make_node(Trivy.VULNERABILITY_REPORT_DIRECTORY_NAME)
        vulnerability_report_directory.mkdir()
        return vulnerability_report_directory

    ## Gets the vulnerability report for a given project. Each project gets its own subdirectory to keep reports organized
    ## in a manner most useful for providing security evidence. So, the resulting report would be written to
    ## `{build_directory}/SoftwareBillOfMaterialsReports/{project_name}/ContainerVulnerabilityReport.html`.
    ## \param[in,out]   project - The project to retrieve the report for.
    ## \return  The vulnerability report for the project.
    @staticmethod
    def GetVulnerabilityReport(project: waflib.TaskGen.task_gen) -> waflib.Node.Node:
        # CONSTRUCT THE VULNERABILITY REPORT FROM THE PROJECT.
        vulnerability_report_directory: waflib.Node.Node = project.bld.bldnode.make_node(Trivy.VULNERABILITY_REPORT_DIRECTORY_NAME)
        project_report_directory: waflib.Node.Node = vulnerability_report_directory.make_node(project.name)
        vulnerability_report: waflib.Node.Node = project_report_directory.make_node('ContainerVulnerabilityReport.html')
        return vulnerability_report

    ## Executes a Trivy vulnerability scan against the Docker image from the provided project. All detected vulnerabilities will be reported,
    ## including vulnerabilities that are not currently "fixable", which means that there is no later version of the package that was flagged
    ## in the vulnerability report where the vulnerability is fixed. Visibility into vulnerabilities that have not yet been fixed is essential
    ## for several types of security reviews, including Authorization to Operate (ATO).
    ## \param[in,out]   project - The project to scan.
    ## \return  A message indicating if vulnerabilities were found in the vulnerability scan and the path to the
    ##      vulnerability report if successful; an error message if unsuccessful.
    @staticmethod
    def ScanDockerImage(project: waflib.TaskGen.task_gen) -> str:
        # VERIFY IF TRIVY CAN ACTUALLY BE USED.
        platform_is_linux: bool = Platform.IsLinux()
        project_includes_docker_image: bool = any(valid_feature in Project(project).GetFeatures() for valid_feature in [DOCKER_FEATURE_NAME])
        trivy_can_be_used: bool = (platform_is_linux and project_includes_docker_image)
        if not trivy_can_be_used:
            # TRIVY CANNOT BE USED IN THIS SCENARIO.
            return 'N/A'

        # CLEAR CACHED RESULTS OF PREVIOUSLY SCANNED DOCKER IMAGES.
        # The Trivy cache directory is used for caching the results of previously scanned Docker images and storing the
        # vulnerability database that Trivy automatically downloads from the Internet.
        #
        # It is necessary to clear the Trivy cache directory of results of previous scanned images in order to ensure
        # that a new vulnerability report is created when a Docker image is scanned a second time. If a Docker image is
        # scanned twice, Trivy will just return the results of the previous scan. This will happen regardless of whether
        # the Docker image has been updated since then or not. This will only change if the Docker image is renamed to
        # something else. If the Trivy cache directory does not yet exist when we request to clear previously scanned Docker
        # images, Trivy will simply do nothing and will not raise an error.
        trivy_cache_directory: waflib.Node.Node = project.bld.bldnode.make_node(Trivy.CACHE_DIRECTORY_NAME)
        Trivy.ClearContainerImageCacheResults(trivy_cache_directory, project.bld)

        # GET THE PATH TO THE TRIVY EXECUTABLE.
        trivy_executable_filepath: str = DevelopmentTools.GetPath(project.env, Trivy.DEVELOPMENT_TOOL_NAME)

        # GET THE PATH TO THE DOCKER IMAGE TAR GZ FILE.
        default_tar_gz_filename: str = f'{project.image_name}.tar.gz'
        relative_docker_image_tar_gz_path: str = getattr(project, 'tar_gz_filepath', default_tar_gz_filename)
        docker_image_tar_gz_absolute_path: str = project.path.find_or_declare(relative_docker_image_tar_gz_path).abspath()

        # SCAN THE DOCKER IMAGE.
        docker_image_vulnerability_report: waflib.Node.Node = Trivy.GetVulnerabilityReport(project)
        # Ensure the parent directory exists before writing.
        docker_image_vulnerability_report.parent.mkdir()
        html_template_file: waflib.Node.Node = project.bld.srcnode.find_node('ThirdParty/Analysis/Trivy/VulnerabilityReportFormats/html.tpl')
        # This is the exit code returned when vulnerabilities are found in a Trivy scan. This value is arbitrary and is only specified
        # because the "trivy image" command returns 0 by default after successfully scanning a Docker image. 21 was picked since
        # this exit code was unlikely to be used for a different purpose.
        VULNERABILITIES_FOUND_EXIT_CODE: int = 21
        trivy_image_command: List[str] = [
            trivy_executable_filepath,
            f'--cache-dir={trivy_cache_directory}',
            'image',
            # The "--exit-code" command line option is used to indicate when Trivy has found vulnerabilities in a scan.
            # This is done in order to tell when Trivy has found vulnerabilities in a vulnerability scan.
            # If Trivy is configured to format the vulnerability report in a specific template, then it will not output the amount of
            # vulnerabilities found in the scan on the command line. Thus, the "--exit-code" command line option is necessary in order
            # to tell when Trivy has actually found vulnerabilities in a Docker image without directly looking at the report.
            f'--exit-code={VULNERABILITIES_FOUND_EXIT_CODE}',
            '--format=template',
            # The HTML format was chosen over other formats for two reasons: better readability and the fact that links to the bug reports
            # of package vulnerabilities are included in the HTML report. Re-evaluate this in the future to determine if another report
            # format can better suit our needs.
            f'--template=@{html_template_file}',
            f'--input={docker_image_tar_gz_absolute_path}',
            f'--output={docker_image_vulnerability_report}']

        # EXECUTE THE SCAN AND RETURN THE RESULT MESSAGE.
        vulnerability_scan_result_message: str = Trivy.GenerateTrivyVulnerabilityReport(
            build_context = project.bld,
            trivy_command = trivy_image_command,
            scan_target_description = docker_image_tar_gz_absolute_path,
            vulnerability_report = docker_image_vulnerability_report,
            vulnerabilities_found_exit_code = VULNERABILITIES_FOUND_EXIT_CODE)
        return vulnerability_scan_result_message

    ## Executes a Trivy vulnerability scan against an SBOM file.
    ## \param[in,out]   build_context - The build context.
    ## \param[in]   sbom_file - The SBOM file to scan.
    ## \param[in]   report_name - The name to use for the vulnerability report (without extension).
    ## \param[in]   project_name - The name of the project this SBOM belongs to. Used to organize reports in project subfolders.
    ## \return  A message indicating if vulnerabilities were found in the vulnerability scan and the path to the
    ##      vulnerability report if successful; an error message if unsuccessful.
    @staticmethod
    def ScanSbom(build_context: waflib.Build.BuildContext, sbom_file: waflib.Node.Node, report_name: str, project_name: str) -> str:
        # VERIFY IF TRIVY CAN ACTUALLY BE USED.
        platform_is_linux: bool = Platform.IsLinux()
        if not platform_is_linux:
            # TRIVY CANNOT BE USED IN THIS SCENARIO.
            return 'N/A'

        # CLEAR CACHED RESULTS OF PREVIOUSLY SCANNED SBOMS.
        # The Trivy cache directory is used for caching the results of previously scanned SBOMs and storing the
        # vulnerability database that Trivy automatically downloads from the Internet.
        #
        # It is necessary to clear the Trivy cache directory of results of previous scanned SBOMs in order to ensure
        # that a new vulnerability report is created when an SBOM is scanned a second time. If an SBOM is
        # scanned twice, Trivy will just return the results of the previous scan. This will happen regardless of whether
        # the SBOM has been updated since then or not. If the Trivy cache directory does not yet exist when we request
        # to clear previously scanned SBOMs, Trivy will simply do nothing and will not raise an error.
        trivy_cache_directory: waflib.Node.Node = build_context.bldnode.make_node(Trivy.CACHE_DIRECTORY_NAME)
        Trivy.ClearContainerImageCacheResults(trivy_cache_directory, build_context)

        # GET THE PATH TO THE TRIVY EXECUTABLE.
        trivy_filepath: str = DevelopmentTools.GetPath(build_context.env, Trivy.DEVELOPMENT_TOOL_NAME)

        # SCAN THE SBOM.
        # Store the report in a project-specific subfolder alongside the Docker image vulnerability report.
        Trivy.CreateVulnerabilityReportDirectory(build_context)
        project_report_folder: str = f'{Trivy.VULNERABILITY_REPORT_DIRECTORY_NAME}/{project_name}'
        sbom_vulnerability_report: waflib.Node.Node = build_context.bldnode.make_node(f'{project_report_folder}/{report_name}.html')
        # Ensure the project-specific subfolder exists.
        sbom_vulnerability_report.parent.mkdir()
        html_template_file: waflib.Node.Node = build_context.srcnode.find_node('ThirdParty/Analysis/Trivy/VulnerabilityReportFormats/html.tpl')
        # This is the exit code returned when vulnerabilities are found in a Trivy scan. This value is arbitrary and is only specified
        # because the "trivy sbom" command returns 0 by default after successfully scanning an SBOM. 21 was picked since
        # this exit code was unlikely to be used for a different purpose.
        VULNERABILITIES_FOUND_EXIT_CODE: int = 21
        trivy_sbom_command: List[str] = [
            trivy_filepath,
            f'--cache-dir={trivy_cache_directory}',
            'sbom',
            # The "--exit-code" command line option is used to indicate when Trivy has found vulnerabilities in a scan.
            # This is done in order to tell when Trivy has found vulnerabilities in a vulnerability scan.
            # If Trivy is configured to format the vulnerability report in a specific template, then it will not output the amount of
            # vulnerabilities found in the scan on the command line. Thus, the "--exit-code" command line option is necessary in order
            # to tell when Trivy has actually found vulnerabilities in an SBOM without directly looking at the report.
            f'--exit-code={VULNERABILITIES_FOUND_EXIT_CODE}',
            '--format=template',
            # The HTML format was chosen over other formats for two reasons: better readability and the fact that links to the bug reports
            # of package vulnerabilities are included in the HTML report. Re-evaluate this in the future to determine if another report
            # format can better suit our needs.
            f'--template=@{html_template_file}',
            sbom_file.abspath(),
            f'--output={sbom_vulnerability_report}']

        # EXECUTE THE SCAN AND RETURN THE RESULT MESSAGE.
        vulnerability_scan_result_message: str = Trivy.GenerateTrivyVulnerabilityReport(
            build_context = build_context,
            trivy_command = trivy_sbom_command,
            scan_target_description = sbom_file.name,
            vulnerability_report = sbom_vulnerability_report,
            vulnerabilities_found_exit_code = VULNERABILITIES_FOUND_EXIT_CODE)
        return vulnerability_scan_result_message
