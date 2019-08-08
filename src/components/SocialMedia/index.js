
import React from "react"
import "./styles.scss"
import { Link, graphql } from "gatsby";
import get from "lodash/get";

class SocialMedia extends React.Component {
  render() {
    
    const posts = get(this, "props.data.allMarkdownRemark.edges");

    return (
      <div>
  
        {posts.map(({ node }) => {
          const title = get(node, "frontmatter.title") || node.fields.slug;
          return (
            <article key={node.fields.slug}>
              <h1>
                <Link style={{ boxShadow: "none" }} to={node.fields.slug}>
                  {title}
                </Link>
              </h1>
              <div dangerouslySetInnerHTML={{ __html: node.html }} />
            </article>
          );
        })}
      </div>
    );
  }
}

export default SocialMedia;

export const SocialMediaQuery = graphql`
  query {
    
    allMarkdownRemark() {
      edges {
        node {
          fields {
            slug
          }
          html
          frontmatter {
            title
          }
        }
      }
    }
  }
`;
