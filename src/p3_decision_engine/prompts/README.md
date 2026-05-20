# Prompts pour le Decision Engine (P3)

## 📁 Structure des Prompts

Ce dossier contient les templates de prompts utilisés par l'IA Featherless pour analyser les vulnérabilités.

## 📋 Fichiers

- **`system_prompt.txt`** : Instructions système pour l'IA (format JSON strict)
- **`user_prompt_template.txt`** : Template pour les requêtes utilisateur avec variables
- **`README.md`** : Documentation des prompts

## 🎯 Utilisation

Les prompts sont actuellement intégrés dans `decision_engine.py` mais peuvent être externalisés pour une meilleure maintenabilité.

### Variables dans le user_prompt :
- `{decision}` : BLOQUER/ALERTER/PASSER
- `{srp_score}` : Score de risque (0-10)
- `{cve_id}` : Identifiant CVE
- `{package}` : Package affecté
- `{desc}` : Description de la vulnérabilité
- `{cisa_notes}` : Notes CISA KEV
- `{actors_str}` : Acteurs de menace identifiés

## 🔧 Intégration Future

Pour externaliser complètement les prompts :
```python
# Charger depuis les fichiers
with open('prompts/system_prompt.txt', 'r') as f:
    system_prompt = f.read()

with open('prompts/user_prompt_template.txt', 'r') as f:
    user_template = f.read()

# Formater avec les variables
user_prompt = user_template.format(
    decision=decision,
    srp_score=srp_score,
    cve_id=cve_id,
    package=package,
    desc=desc,
    cisa_notes=cisa_notes,
    actors_str=actors_str
)
```
