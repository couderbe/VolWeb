import subprocess


class BulkError(Exception):
    pass

"""Analyse with Bulk Extractor"""
def bulk_extractor_analysis(dump_path,case) -> str:
    output_path =  f'Cases/files/bulk_output_{str(case.id)}'
    try:
        output = subprocess.check_output(['bulk_extractor', '-o',output_path, dump_path],timeout=3600)
        print(output)
    except subprocess.CalledProcessError as err:
        raise BulkError(f"Error processing memory dump: {err}")
    except subprocess.TimeoutExpired as err:
        raise BulkError(f"Module timeout: {err}")
    return output_path

def bulk_url_graph(path: str) -> list:
    output = []
    with open(f'{path}/url_histogram.txt') as f:
        while (line:=f.readline()):
            print(line)
            if line[0] != "#":
                spl = line.split("\t")
                print(spl)
                output.append([spl[1],int(spl[0][2:])])
    print(f"output : {output}")
    return output