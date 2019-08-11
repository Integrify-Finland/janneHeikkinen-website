import React from "react"
import './styles.scss'

export const Bold = ({ children }) => <span className="bold">{children}</span>
export const Italic = ({ children }) => (
  <span className="italic">{children}</span>
)
export const Underline = ({ children }) => (
  <span className="Underline">{children}</span>
)

export const H1 = ({ children }) => <h1>{children}</h1>
export const H2 = ({ children }) => <h2>{children}</h2>
export const H3 = ({ children }) => <h3>{children}</h3>
export const H4 = ({ children }) => <h4>{children}</h4>
export const H5 = ({ children }) => <h5>{children}</h5>
export const H6 = ({ children }) => <h6>{children}</h6>

export const Paragraph = ({ children }) => <p>{children}</p>
export const UlLists = ({ children }) => <ul>{children}</ul>
export const OlLists = ({ children }) => <ul>{children}</ul>

export const QUOTE = ({ children }) => <q>{children}</q>
export const HR = ({ children }) => <hr />
export const HYPERLINK = ({ children, node }) => <a href="#">{children}</a>
export const Image = ({ children, url }) => (
  <img src={url} alt="related to the blog post" />
)
