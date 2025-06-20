import json
import glob
def prettify_json(json_file, pretty_json = None):
    with open(json_file, 'r') as f:
        json_data = json.load(f)  

    if pretty_json is None:
        output_file = json_file
    else:
        output_file = pretty_json

    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=4)  

if __name__ == "__main__":
    json_files = glob.glob("reports/*.json")
    
    for json_file in json_files:
        try:
            prettify_json(json_file, )
        except Exception as e:
            print(f" Error al procesar {json_file}: {e}")