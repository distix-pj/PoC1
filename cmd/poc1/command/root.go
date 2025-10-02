package command

import (
	"fmt"

	"errors"
	"io"
	"os"
	"strings"
	"log/slog"
	"path/filepath"
	
	"github.com/spf13/cobra"
	"github.com/awalterschulze/gographviz"
)

var rootCmd *cobra.Command


type RootRunner struct {
  Verbose bool
	InputFile io.Reader
	PkgName string
	MaxDepth int
}
var RootOpts *RootRunner
var inputFile string = ""


func normalizeNodeName(name string) string {
	return strings.Trim(name, `"`)
}

func findExactPackage(graph *gographviz.Graph, packageName string) (string, bool) {
	for nodeName := range graph.Nodes.Lookup {
		if normalizeNodeName(nodeName) == packageName {
			return normalizeNodeName(nodeName), true
		}
	}
	return "", false
}


func findDirectDependents(graph *gographviz.Graph, targetNodeName string) []string {
	var dependents []string
	visited := make(map[string]bool)
	for _, edge := range graph.Edges.Edges {
		if normalizeNodeName(edge.Dst) == targetNodeName {
			srcName := normalizeNodeName(edge.Src)
			if !visited[srcName] {
				visited[srcName] = true
				dependents = append(dependents, edge.Src)
			}
		}
	}
	return dependents
}

type DependentWithDepth struct {
	NodeName string
	Depth    int
}

func findDependentsWithDepth(graph *gographviz.Graph, targetNodeName string, maxDepth int) []DependentWithDepth {
	var result []DependentWithDepth
	visited := make(map[string]bool)
	// Mark TopNode and targetNode as visited 
	visited["RPM-Packages"] = true
	visited[normalizeNodeName(targetNodeName)] = true
	searchAtDepth(graph, targetNodeName, 0, maxDepth, visited, &result)
	return result
}

func searchAtDepth(graph *gographviz.Graph, targetNodeName string, currentDepth, maxDepth int, visited map[string]bool, result *[]DependentWithDepth) {
	// indent := strings.Repeat("\t", currentDepth)
	var queue []string
	if maxDepth > 0 && currentDepth >= maxDepth {
		return
	}
	directDependents := findDirectDependents(graph, targetNodeName)
	for _, depNodeName := range directDependents {
		depNodeName = normalizeNodeName(depNodeName)
		// Check and Mark as visited
		if visited[depNodeName] {
			continue
		}
		visited[depNodeName] = true
		*result = append(*result, DependentWithDepth{
			NodeName: depNodeName,
			Depth:    currentDepth + 1,
		})
		queue = append(queue, depNodeName)
	}
	for _, depNodeName := range queue {
		depNodeName = normalizeNodeName(depNodeName)
		searchAtDepth(graph, normalizeNodeName(depNodeName), currentDepth+1, maxDepth, visited, result)
	}
	return
}



func (r *RootRunner) Run() error {
	targetName := r.PkgName
	maxDepth := r.MaxDepth
	actualMaxDepth := 0
	data, err := io.ReadAll(RootOpts.InputFile)
	if err != nil {
		return err
	}
	graphData, err := gographviz.ParseString(string(data))
	if err != nil {
		return err
	}
	graph := gographviz.NewGraph()
	if err := gographviz.Analyse(graphData, graph); err != nil {
		return err
	}
	if _, found := findExactPackage(graph, targetName) ; !found {
		return errors.New(fmt.Sprintf("%s package is Not Found in your SBOM DOT File.", targetName))
	}

	indirectDependents := findDependentsWithDepth(graph, targetName, maxDepth)
	depthMap := make(map[int][]DependentWithDepth)
	for _, dep := range indirectDependents {
		depthMap[dep.Depth] = append(depthMap[dep.Depth], dep)
		if dep.Depth > actualMaxDepth {
			actualMaxDepth = dep.Depth
		}
	}

	for depth := 1; depth <= actualMaxDepth; depth++ {
		deps := depthMap[depth]
		if len(deps) == 0 {
			continue
		}
		fmt.Printf("depth %d (num %d):\n", depth, len(deps))
		for i, dep := range deps {
			fmt.Printf("\t%d. %s\n", i+1, dep.NodeName)
		}
	}

	return nil
}

func (r *RootRunner) Setup() error {
  loglevel := slog.LevelInfo
  if r.Verbose {
    loglevel = slog.LevelDebug
  }
  handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: loglevel,
  })
  logger := slog.New(handler)
  slog.SetDefault(logger)

  if inputFile == "" {
    // r.InputFile = os.Stdin
		return errors.New(fmt.Sprintf("Required options: --input-file\n"))
  } else if r.PkgName == "" {
		return errors.New(fmt.Sprintf("Required options: --package\n"))
	} else {
    absPath, err := filepath.Abs(inputFile)
    if err != nil {
      return err
    }
    file, err := os.Open(absPath)
    if err != nil {
      return err
    }
    r.InputFile = file
  }

  slog.Debug(
		"RootRunner Options",
    "options", r,
    "Verbose", r.Verbose,
    // "inputFile", r.InputFile,
    "InputFile", inputFile,
		"PkgName", r.PkgName,
		"MaxDepth", r.MaxDepth,
  )

  return nil
}

func NewRootCmd() *cobra.Command {
  runner := &RootRunner{}
  RootOpts = runner
  cmd := &cobra.Command{
    Use:   "poc1",
    Short: "PoC1",
    // Long: `A longer description here..`
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
      return runner.Setup()
    },
    PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
      if closer, ok := RootOpts.InputFile.(io.Closer); ok {
        return closer.Close()
      }
      return nil
    },
    RunE: func(cmd *cobra.Command, args []string) error {
      return runner.Run()
    },
  }
  cmd.PersistentFlags().BoolVarP(&runner.Verbose, "verbose", "v", false, "Verbose message")
  cmd.PersistentFlags().StringVarP(&inputFile, "input-file", "i", "", "Input file (Required)")
	// cmd.MarkFlagRequired("input-file")
  cmd.PersistentFlags().StringVarP(&runner.PkgName, "package", "p", "", "Target Package Name (Required)")
	// cmd.MarkFlagRequired("package")
  cmd.PersistentFlags().IntVarP(&runner.MaxDepth, "depth", "d", -1, "Max Depth (default -1(unlimited))")
  return cmd
}

func Execute() error {
  err := rootCmd.Execute()
  if err != nil {
    return err
  }
  return nil
}

func initRootCmd() {
  if rootCmd == nil {
    rootCmd = NewRootCmd()
  }
}

func init() {
  initRootCmd()
}

