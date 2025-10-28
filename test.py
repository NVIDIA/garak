import garak
import garak.cli
import my_module

garak.cli.main("--target_type function --target_name my_module#function_name --probes goodside.ThreatenJSON".split())
