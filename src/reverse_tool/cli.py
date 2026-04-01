"""CLI entry point for ReverseTool."""

from __future__ import annotations

import logging
import platform
import shutil

import rich_click as click

import reverse_tool
from reverse_tool.discovery import discover_extractors

click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.USE_MARKDOWN = True


class ExtractorGroup(click.Group):
    """Click group that auto-discovers extractor subcommands."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        builtin = ["backends", "doctor"]
        extractors = sorted(discover_extractors().keys())
        extractor_cmds = [n.replace("_", "-") for n in extractors]
        return builtin + extractor_cmds

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        # Builtin commands
        if cmd_name == "backends":
            return backends_cmd
        if cmd_name == "doctor":
            return doctor_cmd

        # Dynamic extractor commands
        module_name = cmd_name.replace("-", "_")
        registry = discover_extractors()
        if module_name in registry:
            return _make_extractor_command(module_name, registry[module_name])

        return None


def _make_extractor_command(
    name: str,
    extractor_cls: type,  # type: ignore[type-arg]
) -> click.Command:
    """Dynamically create a Click command for an extractor."""

    @click.command(name=name.replace("_", "-"))
    @click.option(
        "-b",
        "--backend",
        required=True,
        type=click.Choice(["ghidra", "radare2", "idapro"]),
        help="Analysis backend",
    )
    @click.option(
        "-d",
        "--directory",
        required=True,
        type=click.Path(exists=True),
        help="Binary directory",
    )
    @click.option(
        "-o", "--output", type=click.Path(), default=None, help="Output directory"
    )
    @click.option(
        "-t", "--timeout", type=int, default=600, help="Per-file timeout (seconds)"
    )
    @click.option("--pattern", default=None, help="Glob pattern")
    @click.option(
        "-g",
        "--ghidra-path",
        default=None,
        type=click.Path(),
        help="Path to analyzeHeadless",
    )
    @click.option(
        "-i",
        "--ida-path",
        default=None,
        type=click.Path(),
        help="Path to idat binary",
    )
    @click.pass_context
    def cmd(
        ctx: click.Context,
        backend: str,
        directory: str,
        output: str | None,
        timeout: int,
        pattern: str | None,
        ghidra_path: str | None,
        ida_path: str | None,
    ) -> None:
        from pathlib import Path

        from reverse_tool.backends import get_backend
        from reverse_tool.config import load_config
        from reverse_tool.engine import collect_files, process_files
        from reverse_tool.exceptions import ReverseToolError

        # Config file fallback for backend-specific paths
        config = load_config()
        if ghidra_path is None and config.ghidra_path:
            ghidra_path = config.ghidra_path
        if ida_path is None and config.idapro_path:
            ida_path = config.idapro_path

        directory_path = Path(directory)
        output_dir = (
            Path(output)
            if output
            else directory_path.parent / f"{directory_path.name}_output"
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        backend_cls = get_backend(backend)
        if backend == "ghidra":
            backend_obj = backend_cls(ghidra_path=ghidra_path)  # type: ignore[call-arg]
        elif backend == "idapro":
            backend_obj = backend_cls(ida_path=ida_path)  # type: ignore[call-arg]
        else:
            backend_obj = backend_cls()
        try:
            backend_obj.validate_environment()
        except ReverseToolError as e:
            raise click.ClickException(str(e)) from None

        backend_config = None
        if backend == "ghidra":
            backend_config = str(backend_obj.ghidra_path)  # type: ignore[attr-defined]
        elif backend == "idapro":
            backend_config = str(backend_obj.ida_path)  # type: ignore[attr-defined]

        files = collect_files(directory_path, pattern=pattern)
        if not files:
            click.echo(f"No matching files found in {directory_path}")
            return

        click.echo(f"Processing {len(files)} files with {name} ({backend})")

        succeeded = 0
        failed = 0
        for result in process_files(
            files=files,
            backend_cls=backend_cls,
            extractor_cls=extractor_cls,
            output_dir=output_dir,
            backend_config=backend_config,
            # Sequential for v1.0 stability; parallel via engine API
            max_workers=1,
            timeout=timeout,
        ):
            if result.success:
                succeeded += 1
            else:
                failed += 1

        click.echo(f"Done: {succeeded} succeeded, {failed} failed")

    desc_prop = getattr(extractor_cls, "description", None)
    cmd.help = (
        desc_prop.fget(extractor_cls)  # type: ignore[union-attr]
        if desc_prop is not None and hasattr(desc_prop, "fget")
        else "Extract features"
    )
    return cmd


@click.group(cls=ExtractorGroup)
@click.version_option(version=reverse_tool.__version__, prog_name="reverse-tool")
@click.option("-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)")
@click.option("-q", "--quiet", is_flag=True, help="Suppress output except results")
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool) -> None:
    """ReverseTool - Binary analysis feature extraction framework."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    if quiet:
        level = logging.WARNING
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


@click.command("backends")
def backends_cmd() -> None:
    """List available backends and their status."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Available Backends")
    table.add_column("Backend", style="cyan")
    table.add_column("Status", style="green")

    # Check Ghidra
    ghidra_status = "available" if shutil.which("analyzeHeadless") else "not found"
    table.add_row("ghidra", ghidra_status)

    # Check Radare2
    r2_status = "available" if shutil.which("r2") else "not found"
    table.add_row("radare2", r2_status)

    # Check IDA Pro
    ida_status = "available" if shutil.which("idat") else "not found"
    table.add_row("idapro", ida_status)

    console.print(table)


@click.command("doctor")
def doctor_cmd() -> None:
    """Check environment setup and dependencies."""
    from rich.console import Console

    console = Console()
    console.print(f"[bold]ReverseTool[/bold] v{reverse_tool.__version__}")
    console.print(f"Python:   {platform.python_version()}")
    console.print(f"Platform: {platform.platform()}")

    from reverse_tool.exceptions import BackendNotAvailable, BackendVersionError

    # Ghidra
    ghidra = shutil.which("analyzeHeadless")
    if ghidra:
        from reverse_tool.backends.ghidra import GhidraBackend

        try:
            gb = GhidraBackend(ghidra)
            gb.validate_environment()
            ver = gb.info.version
            console.print(f"Ghidra:   [green]{ver}[/green] ({ghidra})")
        except BackendVersionError as e:
            console.print(
                f"Ghidra:   [red]{e.found}[/red] (requires {e.expected}) ({ghidra})"
            )
        except BackendNotAvailable as e:
            console.print(f"Ghidra:   [red]error[/red] ({e.fix}) ({ghidra})")
        except Exception as e:
            console.print(f"Ghidra:   [yellow]check failed[/yellow] ({e}) ({ghidra})")
    else:
        console.print("Ghidra:   [yellow]not found[/yellow]")

    # Radare2
    r2 = shutil.which("r2")
    if r2:
        from reverse_tool.backends.radare2 import Radare2Backend

        try:
            rb = Radare2Backend()
            rb.validate_environment()
            ver = rb.info.version
            console.print(f"Radare2:  [green]{ver}[/green] ({r2})")
        except BackendVersionError as e:
            console.print(
                f"Radare2:  [red]{e.found}[/red] (requires {e.expected}) ({r2})"
            )
        except BackendNotAvailable as e:
            console.print(f"Radare2:  [red]error[/red] ({e.fix}) ({r2})")
        except Exception as e:
            console.print(f"Radare2:  [yellow]check failed[/yellow] ({e}) ({r2})")
    else:
        console.print("Radare2:  [yellow]not found[/yellow]")

    # IDA Pro
    idat = shutil.which("idat")
    if idat:
        from reverse_tool.backends.idapro import IdaproBackend

        try:
            ib = IdaproBackend(idat)
            ib.validate_environment()
            ver = ib.info.version
            console.print(f"IDA Pro:  [green]{ver}[/green] ({idat})")
        except BackendVersionError as e:
            console.print(
                f"IDA Pro:  [red]{e.found}[/red] (requires {e.expected}) ({idat})"
            )
        except BackendNotAvailable as e:
            console.print(f"IDA Pro:  [red]error[/red] ({e.fix}) ({idat})")
        except Exception as e:
            console.print(f"IDA Pro:  [yellow]check failed[/yellow] ({e}) ({idat})")
    else:
        console.print("IDA Pro:  [yellow]not found[/yellow]")

    # Extractors
    registry = discover_extractors()
    console.print(f"Extractors: {len(registry)} registered")
    for name in sorted(registry):
        console.print(f"  - {name}")
