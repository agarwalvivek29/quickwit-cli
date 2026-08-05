package cli

import (
	"context"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/agarwalvivek29/quickwit-cli/internal/qw"
)

func newIndexesCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "indexes",
		Aliases: []string{"index", "idx"},
		Short:   "Inspect Quickwit indexes",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List indexes",
			Args:  cobra.NoArgs,
			RunE:  func(c *cobra.Command, _ []string) error { return app.indexesList(c.Context()) },
		},
		&cobra.Command{
			Use:   "describe <index>",
			Short: "Show index stats and timestamp range",
			Args:  cobra.ExactArgs(1),
			RunE:  func(c *cobra.Command, args []string) error { return app.indexDescribe(c.Context(), args[0]) },
		},
		newFieldsCmd(app),
	)
	return cmd
}

// newFieldsCmd is a subcommand of `indexes` that prints the field schema.
func newFieldsCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "fields <index>",
		Short: "List the queryable fields (doc mapping) of an index",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.indexFields(c.Context(), args[0]) },
	}
}

func (a *App) indexesList(ctx context.Context) error {
	client, _, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	idxs, err := client.ListIndexes(ctx)
	if err != nil {
		return err
	}
	if len(idxs) == 0 {
		fmt.Fprintln(a.Err, "no indexes")
		return nil
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i].ID() < idxs[j].ID() })
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "INDEX\tTIMESTAMP FIELD\tURI")
	for _, m := range idxs {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.ID(), m.IndexConfig.DocMapping.TimestampField, m.IndexConfig.IndexURI)
	}
	return tw.Flush()
}

func (a *App) indexDescribe(ctx context.Context, id string) error {
	client, _, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	d, err := client.DescribeIndex(ctx, id)
	if err != nil {
		return err
	}
	if a.Output == outJSON {
		return writeJSONValue(a.Out, d)
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "index\t%s\n", d.IndexID)
	fmt.Fprintf(tw, "published docs\t%d\n", d.NumPublishedDocs)
	fmt.Fprintf(tw, "published splits\t%d\n", d.NumPublishedSplits)
	fmt.Fprintf(tw, "size (uncompressed)\t%d bytes\n", d.SizePublishedDocsUncompressed)
	fmt.Fprintf(tw, "timestamp field\t%s\n", d.TimestampFieldName)
	fmt.Fprintf(tw, "min timestamp\t%s\n", fmtEpochPtr(d.MinTimestamp))
	fmt.Fprintf(tw, "max timestamp\t%s\n", fmtEpochPtr(d.MaxTimestamp))
	return tw.Flush()
}

func (a *App) indexFields(ctx context.Context, id string) error {
	client, _, err := a.authedClient(ctx)
	if err != nil {
		return err
	}
	m, err := client.GetIndexMetadata(ctx, id)
	if err != nil {
		return err
	}
	rows := flattenFields("", m.IndexConfig.DocMapping.FieldMappings)
	if a.Output == outJSON {
		return writeJSONValue(a.Out, m.IndexConfig.DocMapping.FieldMappings)
	}
	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "FIELD\tTYPE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], r[1])
	}
	return tw.Flush()
}

// flattenFields walks the (possibly nested) doc mapping into (dotted-name, type)
// rows.
func flattenFields(prefix string, fms []qw.FieldMapping) [][2]string {
	var out [][2]string
	for _, f := range fms {
		name := f.Name
		if prefix != "" {
			name = prefix + "." + f.Name
		}
		if len(f.FieldMappings) > 0 {
			out = append(out, flattenFields(name, f.FieldMappings)...)
			continue
		}
		out = append(out, [2]string{name, f.Type})
	}
	return out
}
