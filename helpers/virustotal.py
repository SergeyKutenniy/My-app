import requests


API_KEY = '53fc8fcb34397a326376729f594ce29fae66a137ba312f6bf4854ec385dcd67b'
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
FILE_INFO_URL = "https://www.virustotal.com/api/v3/files"

def upload_file(path):
    try:
        # Загружаем файл с помощью POST
        with open(path, "rb") as f:
            files = {"file": (path, f)}
            headers = {"x-apikey": API_KEY}
            response = requests.post(UPLOAD_URL, headers=headers, files=files)

        if response.status_code == 200:
            # Получаем ID файла
            file_id = response.json().get("data", {}).get("id")
            if not file_id:
                return {"error": "File ID not found in upload response."}

            # Запрашиваем результаты анализа через другой URL
            result_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
            result_response = requests.get(result_url, headers={"x-apikey": API_KEY})

            if result_response.status_code == 200:
                data = result_response.json().get("data", {}).get("attributes", {})
                # Парсинг результатов анализа
                engine_results = {
                    "malicious": [],
                    "harmless": [],
                    "suspicious": [],
                    "undetected": []
                }

                last_analysis_results = data.get("results", {})
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    engine_info = {
                        "engine": engine,
                        "result": result.get("result", "N/A"),
                        "engine_version": result.get("engine_version", "N/A"),
                        "update": result.get("update", "N/A"),
                    }
                    if category in engine_results:
                        engine_results[category].append(engine_info)

                return {
                    "malicious_count": len(engine_results["malicious"]),
                    "harmless_count": len(engine_results["harmless"]),
                    "suspicious_count": len(engine_results["suspicious"]),
                    "undetected_count": len(engine_results["undetected"]),
                    "engine_results": engine_results
                }
            else:
                return {"error": f"Error fetching analysis results: {result_response.status_code}"}
        else:
            return {"error": f"Error uploading file: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
    
def parse_analysis_results(results):
    if not results:
        return {"error": "No analysis results available."}

    engine_results = {
        "malicious": [],
        "clean": [],
        "undetected": []
    }

    for engine, result in results.items():
        category = result.get("category")
        engine_info = {
            "engine": engine,
            "result": result.get("result", "N/A"),
            "version": result.get("engine_version", "N/A"),
            "update": result.get("engine_update", "N/A")
        }
        if category == "malicious":
            engine_results["malicious"].append(engine_info)
        elif category == "clean":
            engine_results["clean"].append(engine_info)
        else:
            engine_results["undetected"].append(engine_info)

    return {
        "malicious_count": len(engine_results["malicious"]),
        "clean_count": len(engine_results["clean"]),
        "undetected_count": len(engine_results["undetected"]),
        "engine_results": engine_results
    }
