const fs = require('fs');
const { exit } = require('process');

const valueSetPath = "../ehn-dcc-valuesets/"

const valueSetNames = [
    "country-2-codes",
    "test-manf",
    "test-type",
    "vaccine-medicinal-product",
    "disease-agent-targeted",
    "test-result",
    "vaccine-mah-manf",
    "vaccine-prophylaxis"
]

var valueSet = {}

for (let i = 0; i < valueSetNames.length; i++) {
    let valueSetText = fs.readFileSync(valueSetPath + valueSetNames[i] + ".json", "utf8")
    let valueSetObj = JSON.parse(valueSetText)
    valueSet[valueSetNames[i]] = valueSetObj
}

let allValueSets = JSON.stringify(valueSet)
fs.writeFileSync("www/assets/value-sets.json", allValueSets)

