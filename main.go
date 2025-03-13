package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const FALCO_RULES_URL = "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml"

// Загружает оригинальный файл правил Falco
func downloadFalcoRules(outputFile string) error {
	resp, err := http.Get(FALCO_RULES_URL)
	if err != nil {
		return fmt.Errorf("failed to download Falco rules: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download Falco rules: HTTP status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	return ioutil.WriteFile(outputFile, body, 0644)
}

// modifyRules добавляет макрос и изменяет condition
func modifyRules(inputFile, outputFile, namespace string) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	reRule := regexp.MustCompile(`^\s*-\s*rule:\s*(.*)$`) // Исправленное регулярное выражение
	reConditionStart := regexp.MustCompile(`^\s*condition:\s*>?\s*$`)
	reConditionBody := regexp.MustCompile(`^\s{4}.*$`)

	var modifiedLines []string
	macroAdded := false
	inRulesSection := false
	modifyingCondition := false
	conditionBuffer := []string{}

	for _, line := range lines {
		trimLine := strings.TrimSpace(line)

		// Отладка: вывод текущей строки и результата проверки reRule
		fmt.Println("Processing line:", trimLine)
		fmt.Println("Does it match reRule?", reRule.MatchString(trimLine))

		// Добавляем макрос перед первым `rule:`
		if reRule.MatchString(trimLine) && !macroAdded {
			fmt.Println("Adding macro before the first rule")
			modifiedLines = append(modifiedLines, fmt.Sprintf("- macro: not_%s_namespace", namespace))
			modifiedLines = append(modifiedLines, fmt.Sprintf("  condition: k8s.ns.name != \"%s\"", namespace))
			modifiedLines = append(modifiedLines, "")
			macroAdded = true
		}

		// Определяем, находимся ли мы в секции rules
		if reRule.MatchString(trimLine) {
			fmt.Println("Entering rules section:", trimLine)
			inRulesSection = true
		}

		// Логирование состояния inRulesSection
		fmt.Println("inRulesSection:", inRulesSection)

		// Обнаружили начало `condition: >`
		if reConditionStart.MatchString(trimLine) && inRulesSection {
			fmt.Println("Found condition start:", trimLine)
			modifyingCondition = true
			conditionBuffer = []string{line} // Сохраняем строку `- condition: >`
			fmt.Println("Condition buffer initialized:", conditionBuffer)
			inRulesSection = false
			continue
		}

		// Собираем многострочный `condition:`
		if modifyingCondition {
			if reConditionBody.MatchString(line) {
				fmt.Println("Adding to condition buffer:", line)
				conditionBuffer = append(conditionBuffer, line)
				continue
			} else {
				// Закончили читать condition → модифицируем
				fmt.Println("End of condition detected, modifying...")
				originalCondition := strings.Join(conditionBuffer[1:], "\n")
				modifiedCondition := fmt.Sprintf("    not_%s_namespace and (\n%s\n    )", namespace, originalCondition)

				modifiedLines = append(modifiedLines, conditionBuffer[0]) // `- condition: >`
				modifiedLines = append(modifiedLines, modifiedCondition)
				modifyingCondition = false
			}
		}

		modifiedLines = append(modifiedLines, line)
	}

	// Записываем исправленный файл
	return ioutil.WriteFile(outputFile, []byte(strings.Join(modifiedLines, "\n")), 0644)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <output.yaml> <namespace>")
		os.Exit(1)
	}

	outputFile := os.Args[1]
	namespace := os.Args[2]
	tempRulesFile := "falco_rules.yaml"

	if err := downloadFalcoRules(tempRulesFile); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := modifyRules(tempRulesFile, outputFile, namespace); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Rules updated successfully! Falco now ignores the namespace '%s'.\n", namespace)
}
