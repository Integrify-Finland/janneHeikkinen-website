/* eslint-disable react/no-danger */
// @flow
/* eslint-disable react/destructuring-assignment */
/* eslint-disable react/prefer-stateless-function */
/* eslint-disable react/jsx-no-literals */
import React from 'react'

export default class HTML extends React.Component {
  render() {
    return (
      // eslint-disable-next-line jsx-a11y/html-has-lang
      <html {...this.props.htmlAttributes}>
        <head>
          <meta charSet="utf-8" />
          <meta httpEquiv="x-ua-compatible" content="ie=edge" />
          <meta
            name="viewport"
            content="width=device-width, initial-scale=1, shrink-to-fit=no"
          />

          <title>Janne</title>
          {this.props.headComponents}
        </head>
        <body {...this.props.bodyAttributes}>
          {this.props.preBodyComponents}
          <div
            key="body"
            id="___gatsby"
            dangerouslySetInnerHTML={{ __html: this.props.body }}
          />
          {this.props.postBodyComponents}
          <script src="https://cdn.lightwidget.com/widgets/lightwidget.js"></script>
        </body>
      </html>
    )
  }
}
