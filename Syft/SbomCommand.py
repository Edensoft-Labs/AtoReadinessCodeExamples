## \package Waf.Commands.Informational.SbomCommand
## Defines the `sbom` command for generating CycloneDX-compliant Software Bill of Materials (SBOM) in JSON format.
## An SBOM is a formal record containing the details and supply chain relationships of various components used in
## building software. A properly defined SBOM, which includes both first-party and third-party software components,
## is very important for obtaining Authorization to Operate (ATO) in U.S. Department of Defense (DoD) contexts.
## According to the Cybersecurity and Infrastructure Security Agency (CISA), the following are the minimum elements
## of an SBOM (see https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom
## for the most recent version of the CISA guidance as of this writing). The following is quoted from the CISA guidance:
##  - SBOM Author: The name of the entity that creates the SBOM data for this component.
##  - Software Producer: The name of an entity that creates, defines, and identifies components.
##  - Component Name: The name assigned by the Software Producer to a software component.
##  - Component Version: Identifier used by the Software Producer to specify a change in software from a previously identified version.
##  - Software Identifiers: Identifier(s) used to identify a component or serve as a look-up key for relevant databases.
##  - Component Hash: The cryptographic value generated from taking the hash of the software component.
##  - License: The license(s) under which the software component is made available.
##  - Dependency Relationship: The relationship between two software components, specifically noting that Software X includes
##      Component Y or that Component A is largely derived from Component B.
##  - Tool Name: The name of the tool used by the SBOM Author to generate the SBOM.
##  - Timestamp: Record of the date and time of the most recent update to the SBOM data.
##  - Generation Context: The relative software lifecycle phase and data available at the time the Software Producer generated
##      the SBOM (before build, during build, after build).
##
## While neither CISA nor DoD mandate a specific machine-readable SBOM format, we have chosen the CycloneDX format above the
## Software Package Data eXchange (SPDX) format. This is because CycloneDX was designed for supply-chain security: dependency graphs,
## cryptographic hashes, VEX, component pedigree, provenance, and build metadata. These map neatly onto DoD mandates for vulnerability
## management, software supply-chain risk assessments, runtime posture, artifact traceability, and so forth. Because of this,
## commercial scanners, SCA tools, and DoD-preferred platforms (Anchore Enterprise, Aqua, Sonatype, etc.) all use CycloneDX more actively
## in security posture workflows. SPDX, by contrast, was historically a licensing documentation format. It can express security data, but
## it has not proven to be the industry-preferred format. Thus, this Waf command outputs SBOMs in CycloneDX format for easy interoperability with other tools.

import datetime
import optparse
import textwrap
from typing import Optional

import waflib

from Waf.Commands.CustomBaseBuildCommand import CustomBaseBuildContext
from Waf.DevelopmentTools.Syft import Syft
from Waf.Projects.DotNetProject import DotNetProject
from Waf.Projects.Project import Project

## Adds the options for the `sbom` command.
## \param[in,out]   options_context - The context for configuring and updating the available options.
def options(options_context: waflib.Options.OptionsContext):
    # CREATE A GROUP TO HOLD OPTIONS FOR THE SBOM COMMAND.
    sbom_command_option_group: optparse.OptionGroup = options_context.add_option_group("SBOM options")

    # DEFINE THE COMMAND LINE ARGUMENTS.
    # Add an option to specify the SBOM document version number.
    # The SBOM version is the version number of the SBOM document itself (not the software version).
    # It starts at 1 and should be incremented whenever the SBOM is revised for a released artifact.
    # This is a command-line option rather than being automated because SBOM document versioning is a manual
    # compliance activity - the user must decide when they are revising an existing SBOM versus creating a
    # new one. This decision cannot easily be automatically inferred.
    sbom_command_option_group.add_option(
        '--sbom_document_version',
        type = 'int',
        default = 1,
        help = "The version number of the SBOM document, which will be stored in the SBOM's metadata section. Increment when revising an SBOM for the same artifact.")

## Generates CycloneDX-compliant SBOMs in JSON format for the target projects. Such SBOMs contain three major sections:
##  - Metadata. Information like the tool that generated the SBOM, and such. CISA's Minimum SBOM Elements consider this metadata very important.
##  - Components. A declaration of each "software component" in the system, including all necessary versioning, licensing, cryptographic hash,
##      and additional information. In our Waf build system, individual Waf projects are generally treated as the individual "software components"
##      that must be declared to meet the CISA Minimum SBOM Elements guidance. See the above discussion of CISA's Minimum SBOM Elements for more
##      information on software components. Very importantly, each component MUST contain an ID that is unique within this SBOM.
##      CycloneDX calls this unique ID a `bom-ref`.
##  - Dependencies. A mapping from each component to that component's immediate dependencies, done by each component's `bom-ref`. CycloneDX tools
##      reconstruct the complete transitive dependency graph themselves.
##
## This command is primarily designed for Waf projects that build Docker container images, though a Custom Software SBOM (see below) can be generated for
## any type of project. (Container Image SBOMs are currently available for Docker container projects.)
##
## This command generates two top-level SBOM files for each target project, although they are part of one "logical" SBOM:
##  - Custom Software SBOM: Generated from Waf's dependency graph, as well as third-party dependencies for JavaScript/.NET projects that are not
##      reported in the Waf dependency graph. This SBOM is essential for properly declaring all first-party software components and reporting
##      dependencies that may not be detectable in a container image, such as statically linked third-party C++ libraries.
##  - Container Image SBOM: Generated by scanning the built container image using Syft. This SBOM captures all operating system (OS)-level
##      libraries and packages present in the container. It is possible that third-party Python libraries and some other items could be reported
##      in both the Custom Software SBOM and this SBOM. This is not a problem unless the two SBOM files report inconsistent version information for
##      the same library, which has not occurred in testing and is not expected to happen unless there is inaccurate information in the Waf dependency graph or a bug in Syft.
## Other ancillary SBOM files might be created, but they will be merged into these two files.
##
## If you run this command on a project, that project itself will be reported as a component in the `components` array (not just its dependencies),
## along with a corresponding entry in the `dependencies` array showing its immediate dependencies. In other words, the target project is treated
## as a first-class component in its own SBOM, appearing alongside all of its transitive dependencies.
##
## Keeping these sections as separate files rather than merging them into a single JSON file is totally acceptable for
## U.S. Department of Defense (DoD) Authorization to Operate (ATO) requirements and avoids much additional complexity within this Waf command.
class SbomContext(CustomBaseBuildContext):
    # The comment below provides the help text for the command-line.
    '''Generates CycloneDX-compliant SBOMs (Software Bills of Materials) for the target projects'''

    ## Set the command name for the command line.
    cmd = 'sbom'

    ## The name and version number of the Waf SBOM Command tool itself. The CISA Minimum SBOM Elements guidance requires that every SBOM include both the
    ## name AND version of the tool(s) that generated it. This is critical for security auditing and compliance.
    COMMAND_NAME: str = "Waf SBOM Command"
    ## This version should be incremented when the command's functionality changes. This version number is distinct from both the SBOM document version
    ## (which tracks revisions to a specific SBOM) and the product version (which tracks the software being described in the SBOM).
    COMMAND_VERSION: str = '1.0.0'

    ## Generates the SBOMs for the target project(s).
    def Execute(self):
        # GENERATE SBOMs FOR EACH TARGET PROJECT.
        target_projects: list[Project] = Project.CreateForEach(self.TargetProjects)
        for target_project in target_projects:
            # GENERATE THE INITIAL CUSTOM SOFTWARE SBOM FOR THIS PROJECT.
            # This SBOM will later become the Custom Software SBOM once any dependencies outside the Waf dependency graph are added to it.
            project_to_unique_project_id_lookup: dict[Project, str] = {}
            custom_software_sbom_file: waflib.Node.Node = self._GenerateInitialCustomSoftwareSbom(target_project, project_to_unique_project_id_lookup)

            # ENSURE THIRD-PARTY .NET AND JAVASCRIPT PROJECTS ARE INCLUDED IN THE CUSTOM SOFTWARE SBOM.
            # This is necessary because both types of projects can have dependencies that are not reflected in the
            # Waf dependency graph. To produce an accurate accounting of software in the SBOM, then, we must create
            # separate SBOMs for these projects in these instances. This now forms a more complete SBOM for our custom software and its dependencies.
            self._IncludeDotNetDependenciesInCustomSoftwareSbom(target_project, project_to_unique_project_id_lookup, custom_software_sbom_file)
            self._IncludeJavaScriptDependenciesInCustomSoftwareSbom(target_project, project_to_unique_project_id_lookup, custom_software_sbom_file)

            # GENERATE A CONTAINER IMAGE SBOM FOR THIS PROJECT.
            # In addition to the custom software SBOM generated above, also run Syft on any container image projects to
            # generate SBOMs that capture system-level packages and dependencies within the container images. If any projects
            # are incompatible with Syft, that command will log the warning - we don't have to worry about filtering them here.
            Syft.GenerateSbomForContainerImage(target_project.TaskGenerator)

    ## Generates an initial custom software SBOM for the specified project. At this stage, the SBOM solely contains information from the Waf dependency graph,
    ## without other third-party dependencies that might not be reflected in the Waf dependency graph (like NuGet packages or other JavaScript libraries
    ## that are included in a pre-built version of a JavaScript project).
    ## This SBOM contains all Waf projects in the dependency graph along with their relationships.
    ## \param[in]   target_project - The target project to generate the SBOM for.
    ## \param[in,out]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \return  The generated SBOM file.
    def _GenerateInitialCustomSoftwareSbom(self, target_project: Project, project_to_unique_project_id_lookup: dict[Project, str]) -> waflib.Node.Node:
        # LOAD THE PROJECT.
        target_project.TaskGenerator.post()

        # GENERATE SBOM COMPONENT JSON OBJECTS FOR THE PROJECT AND ITS DEPENDENCIES.
        # In CycloneDX, components define all of the pieces of software in a system, with each component having appropriate identifying metadata.
        sbom_component_json_objects: list[dict] = self._GetSbomComponentJsonObjectsForProjectAndDependencies(target_project, project_to_unique_project_id_lookup)

        # GENERATE SBOM DEPENDENCY RELATIONSHIPS FOR ALL COMPONENTS.
        # In CycloneDX, a "dependency" JSON object is NOT another component declaration - it describes the
        # relationship between components defined previously.
        sbom_dependency_json_objects: list[dict] = self._GetSbomDependencyJsonObjects(project_to_unique_project_id_lookup)

        # CREATE THE CUSTOM SOFTWARE SBOM FOR THIS PROJECT.
        # The CycloneDX SBOM spec expects the timestamp to be in UTC and in ISO 8601 format.
        sbom_creation_timestamp_in_utc: str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sbom_json_object = {
            "bomFormat": "CycloneDX",
            # This indicates which CycloneDX specification the SBOM conforms to. As of this writing, the latest CycloneDX specification is 1.6.
            "specVersion": "1.6",
            # This is the version number of the SBOM document itself. It starts at 1 and increments whenever you increment or revise
            # the SBOM for the same artifact. In other words, if you produce a new SBOM due to a build change, dependency update, or
            # corrected metadata, you bump version. It is not the version of your software.
            "version": waflib.Options.options.sbom_document_version,
            "metadata": {
                # This section is important to provide the timestamp and generating tool name/version, which are required CISA Minimum SBOM Elements.
                "timestamp": sbom_creation_timestamp_in_utc,
                "tools": [
                    {
                        "name": self.COMMAND_NAME,
                        "version": self.COMMAND_VERSION
                    }
                ]
            },
            "components": sbom_component_json_objects,
            "dependencies": sbom_dependency_json_objects
        }

        # SAVE THE SBOM TO A FILE.
        sbom_report_directory: waflib.Node.Node = target_project.TaskGenerator.bld.bldnode.make_node(Syft.SBOM_REPORT_DIRECTORY_NAME)
        project_sbom_directory: waflib.Node.Node = sbom_report_directory.make_node(target_project.Name)
        initial_custom_software_sbom_file: waflib.Node.Node = project_sbom_directory.make_node('CustomSoftwareSbom.json')
        # Ensure the parent directory exists before attempting to create a file within it.
        initial_custom_software_sbom_file.parent.mkdir()
        initial_custom_software_sbom_file.write_json(sbom_json_object)
        waflib.Logs.info(f'Initial Custom Software SBOM for {target_project.Name} saved to {initial_custom_software_sbom_file}.')
        return initial_custom_software_sbom_file

    ## Generates .NET dependency SBOMs for each .NET Waf project identified in the current Waf projects we are processing
    ## and merges these SBOMs into the main Custom Software SBOM. Currently, NuGet package dependencies of .NET Waf projects
    ## are not reflected in the Waf dependency graph. Thus, such NuGet packages will not appear in SBOMs, which would violate
    ## the requirement that SBOMs disclose all the software components in the system under consideration. To properly include these
    ## dependencies in SBOMs, we must give NuGet package metadata to the SBOM generator manually so it can generate a more complete SBOM.
    ## \param[in]   target_project - The target project being built, used for determining the SBOM directory location.
    ## \param[in]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \param[in]   custom_software_sbom_file - The main Custom Software SBOM file into which  dependencies into.
    def _IncludeDotNetDependenciesInCustomSoftwareSbom(self, target_project: Project, project_to_unique_project_id_lookup: dict[Project, str], custom_software_sbom_file: waflib.Node.Node):
        # CREATE AN SBOM FOR EACH .NET PROJECT UNDER CONSIDERATION.
        DOT_NET_FEATURE_NAMES: set[str] = {'dot_net', 'dot_net_framework', 'asp_net_website', 'asp_net_library'}
        for project in project_to_unique_project_id_lookup.keys():
            # CHECK IF THIS IS A .NET PROJECT.
            dependency_features: set[str] = project.GetFeatures()
            dependency_is_dot_net: bool = not dependency_features.isdisjoint(DOT_NET_FEATURE_NAMES)
            if not dependency_is_dot_net:
                # MOVE ON TO THE NEXT PROJECT.
                # We don't need to issue any log message in this instance.
                continue

            # VERIFY THE .NET PROJECT'S BUILD FOLDER EXISTS.
            dot_net_project: DotNetProject = DotNetProject(project.TaskGenerator)
            build_folder: waflib.Node.Node = dot_net_project.GetBuildFolder()
            if not build_folder.exists():
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    Build folder does not exist for .NET project {project.Name}. The project may not have been built yet.
                    NuGet dependencies for this project will be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue

            # VERIFY THE DEPENDENCY METADATA EXISTS.
            # The packages.lock.json file is generated upon build when the RestorePackagesWithLockFile setting is enabled
            # in the C# project definition file (CSPROJ). This file contains all NuGet package dependencies, and is what
            # SBOM generators expect to ingest to generate SBOMs for .NET projects.
            nuget_lock_file: waflib.Node.Node = build_folder.find_node('packages.lock.json')
            nuget_lock_file_exists: bool = nuget_lock_file is not None
            if not nuget_lock_file_exists:
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    NuGet lock file (packages.lock.json) not found for .NET project {project.Name}. If there are NuGet dependencies for
                    this project, these dependencies will be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue

            # GENERATE AN SBOM BASED ON THIS PROJECT'S DEPENDENCY METADATA.
            dependency_metadata_sbom_file: waflib.Node.Node = Syft.GenerateSbomForFilesystem(
                project = project.TaskGenerator,
                directory_to_scan = build_folder,
                output_directory_name = target_project.Name)
            dependency_metadata_sbom_file_exists: bool = (dependency_metadata_sbom_file is not None) and (dependency_metadata_sbom_file.exists())
            if not dependency_metadata_sbom_file_exists:
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    .NET dependency metadata JSON file not found for project {project.Name}. NuGet dependencies for this project
                    will be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue

            # MERGE THESE DEPENDENCIES INTO THE CUSTOM SOFTWARE SBOM.
            self._MergeDependencyMetadataSbomIntoCustomSoftwareSbom(
                project = project,
                project_to_unique_project_id_lookup = project_to_unique_project_id_lookup,
                dependency_metadata_file = dependency_metadata_sbom_file,
                custom_software_sbom_file = custom_software_sbom_file)

    ## Generates JavaScript dependency SBOMs for each JavaScript Waf project identified in the current projects we are processing
    ## and merges these SBOMs into the main Custom Software SBOM. In several instances, we have checked in pre-built versions of
    ## JavaScript libraries that include dependencies not reflected in the Waf dependency graph. Such dependencies will not appear
    ## in SBOMs, which would violate the requirement that SBOMs disclose all the software components in the system under consideration.
    ## To properly include these dependencies in SBOMs, we must give JavaScript package metadata to the SBOM generator manually so it can generate a more complete SBOM.
    ## \param[in]   target_project - The target project being built, used for determining the SBOM directory location.
    ## \param[in]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \param[in]   custom_software_sbom_file - The main Custom Software SBOM file to merge external dependencies into.
    def _IncludeJavaScriptDependenciesInCustomSoftwareSbom(self, target_project: Project, project_to_unique_project_id_lookup: dict[Project, str], custom_software_sbom_file: waflib.Node.Node):
        # CREATE AN SBOM FOR EACH JAVASCRIPT PROJECT UNDER CONSIDERATION.
        JAVASCRIPT_FEATURE_NAME: str = 'javascript'
        for dependency_project in project_to_unique_project_id_lookup.keys():
            # DETERMINE IF WE EXPECT DEPENDENCY METADATA FOR THIS PROJECT.
            # We only look for third-party JavaScript projects because they often come pre-built with bundled dependencies
            # that are not reflected in the Waf dependency graph. First-party JavaScript projects have their dependencies
            # properly tracked through the normal Waf build process and don't require this special handling.
            dependency_features: set[str] = dependency_project.GetFeatures()
            is_javascript_project: bool = JAVASCRIPT_FEATURE_NAME in dependency_features
            is_third_party: bool = Project.IsThirdParty(dependency_project.TaskGenerator)
            dependency_metadata_is_expected: bool = is_javascript_project and is_third_party
            if not dependency_metadata_is_expected:
                # MOVE ON TO THE NEXT PROJECT.
                continue

            # GET THE DEPENDENCY METADATA FOLDER.
            has_dependency_metadata_folder: bool = hasattr(dependency_project.TaskGenerator, 'sbom_dependency_metadata_folder')
            if not has_dependency_metadata_folder:
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    Third-party JavaScript project {dependency_project.Name} does not provide dependency metadata.
                    Its dependencies might be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue
            dependency_metadata_folder_name: str = dependency_project.TaskGenerator.sbom_dependency_metadata_folder
            dependency_metadata_folder: waflib.Node.Node = dependency_project.TaskGenerator.path.make_node(dependency_metadata_folder_name)

            # VERIFY THE DEPENDENCY METADATA FOLDER EXISTS.
            # We cannot easily verify that specific files within this folder exist, because JavaScript projects can track dependencies with multiple
            # different types of metadata files. Thus, we will presume that if such a folder exists, it has been correctly populated for that specific project.
            dependency_metadata_folder_exists: bool = dependency_metadata_folder.exists()
            if not dependency_metadata_folder_exists:
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    Could not find dependency metadata folder for JavaScript project {dependency_project.Name}.
                    Its dependencies might be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue

            # GENERATE AN SBOM BASED ON THIS PROJECT'S DEPENDENCY METADATA.
            dependency_metadata_sbom_file: waflib.Node.Node = Syft.GenerateSbomForFilesystem(
                project = dependency_project.TaskGenerator,
                directory_to_scan = dependency_metadata_folder,
                output_directory_name = target_project.Name)
            javascript_dependency_metadata_sbom_file_exists: bool = (dependency_metadata_sbom_file is not None) and (dependency_metadata_sbom_file.exists())
            if not javascript_dependency_metadata_sbom_file_exists:
                # PROVIDE VISIBILITY INTO THE ISSUE.
                warning_message: str = textwrap.dedent(f'''
                    JavaScript dependency metadata JSON file not found for project {dependency_project.Name}. JavaScript dependencies for this project
                    will be missing from the SBOM, so the SBOM will likely not meet security compliance requirements.''')
                waflib.Logs.warn(warning_message)

                # MOVE ON TO THE NEXT PROJECT.
                continue

            # MERGE THESE DEPENDENCIES INTO THE CUSTOM SOFTWARE SBOM.
            self._MergeDependencyMetadataSbomIntoCustomSoftwareSbom(
                project = dependency_project,
                project_to_unique_project_id_lookup = project_to_unique_project_id_lookup,
                dependency_metadata_file = dependency_metadata_sbom_file,
                custom_software_sbom_file = custom_software_sbom_file)

    ## Creates SBOM components for a project and all its dependencies.
    ## \param[in]   project - The project (along with its dependencies) to be converted to SBOM components.
    ## \param[in,out]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \return  The SBOM component JSON objects for the project and its dependencies.
    ## \throws  waflib.Errors.WafError - Thrown if a project has a duplicate unique ID.
    def _GetSbomComponentJsonObjectsForProjectAndDependencies(self, project: Project, project_to_unique_project_id_lookup: dict[Project, str]) -> list[dict]:
        # GET THE PROJECT AND ALL ITS DEPENDENCIES.
        # Get all transitive dependencies (not just immediate ones).
        dependencies: set[Project] = project.TaskGenerator.bld.ProjectGraph.GetAllDependencies(project)
        # This set includes the project itself along with all its dependencies.
        project_with_dependency_projects: set[Project] = {project} | dependencies

        # GET SBOM COMPONENT JSON OBJECTS FOR THE PROJECT AND ITS DEPENDENCIES.
        sbom_component_json_objects: list[dict] = []
        for current_project in project_with_dependency_projects:
            # SKIP THIS PROJECT IF ALREADY ADDED.
            # This can happen if a project is shared between multiple target projects.
            project_already_added: bool = current_project in project_to_unique_project_id_lookup
            if project_already_added:
                continue

            # GET THE SBOM COMPONENT JSON OBJECT FOR THIS PROJECT.
            component = self._GetSbomComponentJsonObject(current_project)

            # ENSURE THIS PROJECT HAS A UNIQUE ID IN THE SBOM.
            # Check if this project's `bom-ref` is already used by a different project.
            existing_unique_project_ids: set[str] = set(project_to_unique_project_id_lookup.values())
            project_id: str = component["bom-ref"]
            project_id_already_defined: bool = project_id in existing_unique_project_ids
            if project_id_already_defined:
                # RAISE AN ERROR SINCE WE FOUND A DUPLICATE UNIQUE ID.
                # We intentionally raise an error here rather than trying to continue because having duplicate unique IDs would
                # render the SBOM invalid and likely cause SBOM compliance issues. Since unique IDs are typically sourced from
                # Waf project names, duplicate IDs should only occur when IDs are manually overridden. But when they occur,
                # duplicates are an issue that must be fixed.
                error_message: str = textwrap.dedent(f'''Duplicate bom-ref detected in SBOM generation: {project_id}.
                    Each component must have a unique bom-ref.''')
                raise waflib.Errors.WafError(error_message)

            # ADD THE SBOM COMPONENT.
            sbom_component_json_objects.append(component)
            project_to_unique_project_id_lookup[current_project] = project_id

        # RETURN ALL THE SBOM COMPONENTS.
        return sbom_component_json_objects

    ## Creates a CycloneDX component JSON object from a project. Such a component looks like the following:
    ## ```
    ##     {
    ##         "bom-ref": "pkg:pypi/pygit2@1.18.2",
    ##         "type": "library",
    ##         "name": "pygit2",
    ##         "version": "1.18.2",
    ##         "purl": "pkg:pypi/pygit2@1.18.2",
    ##         "licenses":
    ##          [
    ##              {
    ##                 "license":
    ##                  {
    ##                     "name": "GPLv2 with linking exception"
    ##                  }
    ##              }
    ##          ]
    ##     }
    ## ```
    ## There are many other optional fields for CycloneDX JSON components, but we currently do not need to complete those.
    ## \param[in]   project - The project to convert to a component.
    ## \return  The CycloneDX component JSON object.
    def _GetSbomComponentJsonObject(self, project: Project) -> dict:
        # CHECK IF THIS PROJECT IS A DEFAULT VERSION PROJECT.
        # Some projects (like default library versions) don't have their own source code or metadata - they just
        # reference a single versioned project via the `use` attribute. For these "default version" projects, we
        # should inherit metadata from the project they reference rather than issuing warnings about missing metadata.
        inherited_version_project: Optional[Project] = None
        project_is_default_version_project: bool = Project.IsDefaultVersionProject(project.TaskGenerator)
        if project_is_default_version_project:
            # GET THE SINGLE DEPENDENCY THIS DEFAULT VERSION PROJECT POINTS TO.
            immediate_dependencies: set[Project] = project.TaskGenerator.bld.ProjectGraph.GetImmediateDependencies(project)
            inherited_version_project = immediate_dependencies.pop()

        # GET THE PROJECT VERSION NUMBER.
        # According to the CISA Minimum SBOM Elements guidance, even first-party software components must specify a version number.
        version_number: Optional[str] = getattr(project.TaskGenerator, 'version_number', None)
        version_number_provided: bool = version_number is not None
        project_is_default_version_project: bool = inherited_version_project is not None
        version_number_can_be_inherited: bool = (not version_number_provided) and project_is_default_version_project
        if version_number_can_be_inherited:
            # INHERIT THE PROJECT VERSION NUMBER.
            version_number = getattr(inherited_version_project.TaskGenerator, 'version_number', None)
            version_number_provided = version_number is not None
        if not version_number_provided:
            # CHECK IF THE PROJECT IS THIRD-PARTY.
            project_is_third_party: bool = Project.IsThirdParty(project.TaskGenerator)
            if project_is_third_party:
                # SET A PLACEHOLDER PROJECT VERSION NUMBER.
                waflib.Logs.warn(f"No version number provided for third-party project {project.Name}. A generic version number will be used, which likely will not meet security compliance requirements.")
                version_number = "Unknown"
            else:
                # USE THE PRODUCT VERSION FOR FIRST-PARTY SOFTWARE.
                # First-party software version numbers are controlled by the --product_version command line option
                # rather than being hard-coded in individual wscripts. This ensures consistent versioning across
                # all first-party components and ties the SBOM version numbers to the actual product release version.
                version_number = waflib.Options.options.product_version

        # GET THE PROJECT LICENSE NAME.
        license_name: Optional[str] = getattr(project.TaskGenerator, 'license_name', None)
        license_name_provided: bool = license_name is not None
        license_name_can_be_inherited: bool = (not license_name_provided) and project_is_default_version_project
        if license_name_can_be_inherited:
            # INHERIT THE PROJECT LICENSE NAME.
            license_name = getattr(inherited_version_project.TaskGenerator, 'license_name', None)
            license_name_provided = license_name is not None
        if not license_name_provided:
            # DETERMINE IF THE PROJECT IS THIRD-PARTY.
            project_is_third_party: bool = Project.IsThirdParty(project.TaskGenerator)
            if project_is_third_party:
                # SET A PLACEHOLDER LICENSE NAME.
                waflib.Logs.warn(f"No license name provided for third-party project {project.Name}. A generic license name will be used, which likely will not meet security compliance requirements.")
                license_name = "Unknown Third-Party License"
            else:
                # SPECIFY THE LICENSE AS YOUR ORGANIZATION'S PROPRIETARY LICENSE.
                # If the project is not third-party, it is first-party, and thus this code is proprietary. The CISA SBOM Minimum Elements guidance
                # is clear that license information is required for each software component, even first-party components. Setting this here avoids
                # needing to specify the same license name in each and every wscript of first-party projects.
                # REPLACE "Your Organization Proprietary" with your actual license name.
                license_name = "Your Organization Proprietary"

        # GET THE COMPONENT TYPE.
        component_type: Optional[str] = None
        project_is_library: bool = Project.IsLibrary(project.TaskGenerator)
        if project_is_library:
            component_type = "library"
        else:
            component_type = "application"

        # GET THE PACKAGE URL.
        # PURLs (Package URLs) provide a standardized way to identify software components in the CycloneDX SBOM format.
        # These are not URLs that are accessible from a web browser, but rather standardized identifiers that describe
        # a software component's type, namespace, name, and version across different package ecosystems.
        package_url: Optional[str] = getattr(project.TaskGenerator, 'sbom_package_url', None)
        package_url_provided: bool = package_url is not None
        package_url_can_be_inherited: bool = (not package_url_provided) and project_is_default_version_project
        if package_url_can_be_inherited:
            # INHERIT THE PACKAGE URL.
            # Default version projects don't have their own SBOM metadata; they inherit from the versioned project they reference.
            package_url = getattr(inherited_version_project.TaskGenerator, 'sbom_package_url', None)
            package_url_provided = package_url is not None
        project_is_third_party: bool = Project.IsThirdParty(project.TaskGenerator)
        package_url_missing_for_third_party_project: bool = project_is_third_party and (not package_url_provided)
        if package_url_missing_for_third_party_project:
            # USE A GENERIC PACKAGE URL.
            waflib.Logs.warn(f"No SBOM Package Url (PURL) provided for third-party project {project.Name}. A generic PURL will be used, which likely will not meet security compliance requirements.")
            package_url = f'pkg:generic/{project.Name}@{version_number}'

        # GET THE UNIQUE ID (BOM-REF).
        # Every component must have an ID unique to this SBOM (what CycloneDX calls the `bom-ref`), so if a `bom-ref` is
        # not explicitly provided, we must create one.
        unique_id: Optional[str] = getattr(project.TaskGenerator, 'sbom_unique_id', None)
        unique_id_provided: bool = unique_id is not None
        if not unique_id_provided:
            # USE THE PROJECT NAME AS UNIQUE ID.
            # The project name is a great candidate for a unique ID, because project names in Waf should already be unique.
            # There is no need to issue a warning here, because we expect that most projects will just use the project name
            # as their unique ID.
            unique_id = project.Name

        # CREATE THE COMPONENT JSON OBJECT.
        component = {
            "bom-ref": unique_id,
            "type": component_type,
            "name": project.Name,
            "version": version_number,
            "licenses": [
            {
                "license":
                {
                    "name": license_name,
                }
            }]
        }
        # Only include the Package URL if it has a value. According to the CycloneDX spec, a PURL is NOT required to be provided,
        # and it is generally not provided for first-party code. However, if the PURL key is provided in the JSON object, its value
        # must not be null. Otherwise, SBOM validation will fail.
        package_url_was_provided: bool = package_url is not None
        if package_url_was_provided:
            component["purl"] = package_url

        return component

    ## Creates CycloneDX dependency JSON objects for all defined projects, to show relationships between components.
    ## Such dependency objects look like the following:
    ## ```
    ##     {
    ##         "ref": "pkg:deb/debian/base-files@12.4%2Bdeb12u12?arch=amd64&distro=debian-12&package-id=293a3409598783e4",
    ##         "dependsOn":
    ##          [
    ##             "pkg:deb/debian/mawk@1.3.4.20200120-3.1?arch=amd64&distro=debian-12&package-id=81ae31ac445c7dbb"
    ##          ]
    ##     },
    ##     {
    ##         "ref": "pkg:deb/debian/base-passwd@3.6.1?arch=amd64&distro=debian-12",
    ##         "dependsOn":
    ##          [
    ##             "pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12",
    ##             "pkg:deb/debian/libdebconfclient0@0.270?arch=amd64&distro=debian-12",
    ##             "pkg:deb/debian/libselinux1@3.4-1%2Bb6?arch=amd64&distro=debian-12"
    ##          ]
    ##     }
    ## ```
    ## \param[in,out]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \return  The SBOM dependency JSON objects.
    def _GetSbomDependencyJsonObjects(self, project_to_unique_project_id_lookup: dict[Project, str]) -> list[dict]:
        # BUILD THE DEPENDENCY RELATIONSHIPS FOR EACH COMPONENT.
        sbom_dependency_json_objects: list[dict] = []
        for project, unique_id in project_to_unique_project_id_lookup.items():
            # GET THE UNIQUE IDs OF EACH IMMEDIATE DEPENDENCY OF THIS PROJECT.
            # The CycloneDX SBOM specification intends the dependency graph to be explicitly hierarchical, not flattened.
            # Thus, we only need to get the immediate dependencies of this project.
            immediate_dependencies: set[Project] = project.TaskGenerator.bld.ProjectGraph.GetImmediateDependencies(project)
            immediate_dependency_unique_ids: list[str] = [project_to_unique_project_id_lookup[immediate_dependency] for immediate_dependency in immediate_dependencies]

            # CREATE THE DEPENDENCY JSON OBJECT.
            # The CycloneDX SBOM specification requires that every component have a dependency JSON object, even if it has no dependencies.
            dependency_entry_json_object = {
                "ref": unique_id,
                "dependsOn": immediate_dependency_unique_ids
            }
            sbom_dependency_json_objects.append(dependency_entry_json_object)

        # RETURN ALL THE SBOM DEPENDENCY INFORMATION.
        return sbom_dependency_json_objects

    ## Merges a dependency metadata SBOM into the custom software SBOM by adding all CycloneDX component and dependency objects from the dependency metadata SBOM to the
    ## custom software SBOM. Thus, we "link up" the Waf project to the dependency metadata that is not directly present in the Waf dependency graph but still must be reported
    ## in an SBOM, like JavaScript dependencies included in pre-built third-party JavaScript Waf projects and NuGet dependencies for .NET projects.
    ## This adds all JavaScript components from the dependency metadata as direct dependencies of the Waf project.
    ## \param[in]   project - The Waf project that depends on these JavaScript packages.
    ## \param[in]   project_to_unique_project_id_lookup - A lookup from projects to their unique IDs (`bom-ref`s).
    ## \param[in]   dependency_metadata_file - The Syft-generated SBOM with JavaScript dependencies.
    ## \param[in]   custom_software_sbom_file - The Custom Software SBOM file to modify.
    ## \return  True if the merge was successful; False otherwise.
    def _MergeDependencyMetadataSbomIntoCustomSoftwareSbom(
        self,
        project: Project,
        project_to_unique_project_id_lookup: dict[Project, str],
        dependency_metadata_file: waflib.Node.Node,
        custom_software_sbom_file: waflib.Node.Node) -> bool:
        try:
            # ADD ALL COMPONENTS FROM THE DEPENDENCY METADATA SBOM TO THE CUSTOM SOFTWARE SBOM.
            # First, we read the dependency metadata SBOM.
            dependency_metadata_json_object: dict = dependency_metadata_file.read_json()
            components_from_dependency_metadata: list[dict] = dependency_metadata_json_object['components']
            # Then, we read the custom software SBOM.
            custom_software_sbom_json_object: dict = custom_software_sbom_file.read_json()
            components_from_custom_software_sbom: list[dict] = custom_software_sbom_json_object['components']
            # To avoid duplicates, we need to track existing unique IDs.
            unique_ids_initially_defined_in_custom_software_sbom: set[str] = {component['bom-ref'] for component in components_from_custom_software_sbom}
            unique_ids_added_to_custom_software_sbom: list[str] = []
            for component_from_dependency_metadata in components_from_dependency_metadata:
                # SKIP COMPONENTS THAT ARE JUST RAW FILES.
                # We skip these because they represent files (like JavaScript/.NET dependency files themselves), rather than actual dependencies.
                # These files don't need to be included in the SBOM - only the information inside them needs to be included.
                component_type: str = component_from_dependency_metadata['type']
                is_file_type_component: bool = ('file' == component_type)
                if is_file_type_component:
                    continue

                # ADD THIS COMPONENT TO THE CUSTOM SOFTWARE SBOM.
                # There cannot be duplicate unique IDs among the components, so components only need to be added if they don't already exist.
                component_unique_id: str = component_from_dependency_metadata['bom-ref']
                unique_id_already_defined: bool = component_unique_id in unique_ids_initially_defined_in_custom_software_sbom
                if not unique_id_already_defined:
                    # ADD THIS COMPONENT TO THE CUSTOM SOFTWARE SBOM.
                    custom_software_sbom_json_object['components'].append(component_from_dependency_metadata)
                    unique_ids_initially_defined_in_custom_software_sbom.add(component_unique_id)
                    unique_ids_added_to_custom_software_sbom.append(component_unique_id)

            # REPORT ALL DEPENDENCIES FROM THE DEPENDENCY METADATA AS DIRECT DEPENDENCIES OF THE WAF PROJECT.
            # As described above, all dependencies (including transitive ones) are listed as direct dependencies of the
            # Waf project, which is not fully compliant with the CycloneDX specification but is sufficient for current needs.
            #
            # First, we need to build a lookup of dependency entries by their unique IDs.
            project_unique_id: str = project_to_unique_project_id_lookup[project]
            unique_id_to_dependency_entry_lookup: dict[str, dict] = {dependency['ref']: dependency for dependency in custom_software_sbom_json_object['dependencies']}
            waf_project_dependency_entry: dict = unique_id_to_dependency_entry_lookup[project_unique_id]
            direct_dependencies_for_waf_project: list[str] = waf_project_dependency_entry['dependsOn']
            for unique_id in unique_ids_added_to_custom_software_sbom:
                # ADD THE DEPENDENCY TO THE WAF PROJECT'S DEPENDENCIES.
                # There cannot be duplicate unique IDs in the dependencies list, so dependencies only need to be added if they don't already exist.
                dependency_already_added: bool = unique_id in direct_dependencies_for_waf_project
                if not dependency_already_added:
                    # ADD THE DEPENDENCY TO THE WAF PROJECT'S DEPENDENCIES.
                    direct_dependencies_for_waf_project.append(unique_id)
            waf_project_dependency_entry['dependsOn'] = direct_dependencies_for_waf_project

            # WRITE THE UPDATED CUSTOM SOFTWARE SBOM.
            custom_software_sbom_file.write_json(custom_software_sbom_json_object)
            waflib.Logs.info(f'Components and dependencies for {project.Name} merged into Custom Software SBOM.')
            return True

        except Exception as error:
            # PROVIDE VISIBILITY INTO THE ERROR.
            waflib.Logs.warn(f'Failed to merge components and dependencies for {project.Name} into Custom Software SBOM: {error}')
            return False
