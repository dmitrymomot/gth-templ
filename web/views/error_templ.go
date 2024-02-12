// Code generated by templ - DO NOT EDIT.

// templ: version: 0.2.476
package views

//lint:file-ignore SA4006 This context is only used if a nested component is present.

import "github.com/a-h/templ"
import "context"
import "io"
import "bytes"

import (
	"braces.dev/errtrace"
	"fmt"
	"net/http"
)

func ErrorPage(code int, message string) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
		templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
		if !templ_7745c5c3_IsBuffer {
			templ_7745c5c3_Buffer = templ.GetBuffer()
			defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
		}
		ctx = templ.InitializeContext(ctx)
		templ_7745c5c3_Var1 := templ.GetChildren(ctx)
		if templ_7745c5c3_Var1 == nil {
			templ_7745c5c3_Var1 = templ.NopComponent
		}
		ctx = templ.ClearChildren(ctx)
		templ_7745c5c3_Var2 := templ.ComponentFunc(func(ctx context.Context, templ_7745c5c3_W io.Writer) (templ_7745c5c3_Err error) {
			templ_7745c5c3_Buffer, templ_7745c5c3_IsBuffer := templ_7745c5c3_W.(*bytes.Buffer)
			if !templ_7745c5c3_IsBuffer {
				templ_7745c5c3_Buffer = templ.GetBuffer()
				defer templ.ReleaseBuffer(templ_7745c5c3_Buffer)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<main class=\"grid min-h-full place-items-center px-6 py-24 sm:pt-32 lg:pt-56 lg:px-8\"><div class=\"text-center\"><p class=\"text-base font-semibold text-indigo-600 dark:text-indigo-400\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			var templ_7745c5c3_Var3 string = fmt.Sprintf("%d", code)
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var3))
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</p><h1 class=\"mt-4 text-3xl font-bold tracking-tight text-gray-900 dark:text-gray-100 sm:text-5xl\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			var templ_7745c5c3_Var4 string = http.StatusText(code)
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var4))
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</h1><p class=\"mt-6 text-base leading-7 text-gray-600 dark:text-gray-400\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			var templ_7745c5c3_Var5 string = message
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ.EscapeString(templ_7745c5c3_Var5))
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</p><div class=\"mt-10 flex items-center justify-center gap-x-6\"><a href=\"#\" class=\"rounded-md bg-indigo-600 dark:bg-indigo-400 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 dark:hover:bg-indigo-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 dark:focus-visible:outline-indigo-400\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			templ_7745c5c3_Var6 := `Go back home`
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ_7745c5c3_Var6)
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</a> <a href=\"#\" class=\"text-sm font-semibold text-gray-900 dark:text-gray-100\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			templ_7745c5c3_Var7 := `Contact support `
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ_7745c5c3_Var7)
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("<span aria-hidden=\"true\">")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			templ_7745c5c3_Var8 := `&rarr;`
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString(templ_7745c5c3_Var8)
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteString("</span></a></div></div></main>")
			if templ_7745c5c3_Err != nil {
				return errtrace.Wrap(templ_7745c5c3_Err)
			}
			if !templ_7745c5c3_IsBuffer {
				_, templ_7745c5c3_Err = io.Copy(templ_7745c5c3_W, templ_7745c5c3_Buffer)
			}
			return errtrace.Wrap(templ_7745c5c3_Err)
		})
		templ_7745c5c3_Err = Layout(Head{
			Title:       fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Description: message,
		}).Render(templ.WithChildren(ctx, templ_7745c5c3_Var2), templ_7745c5c3_Buffer)
		if templ_7745c5c3_Err != nil {
			return errtrace.Wrap(templ_7745c5c3_Err)
		}
		if !templ_7745c5c3_IsBuffer {
			_, templ_7745c5c3_Err = templ_7745c5c3_Buffer.WriteTo(templ_7745c5c3_W)
		}
		return errtrace.Wrap(templ_7745c5c3_Err)
	})
}
