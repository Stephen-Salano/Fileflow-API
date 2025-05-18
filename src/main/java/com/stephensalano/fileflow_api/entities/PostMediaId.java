package com.stephensalano.fileflow_api.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PostMediaId implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    // These field names must match exactly with the corresponding fields in the PostMedia entity
    private UUID post;   // matches the post field in PostMedia
    private UUID media;  // matches the media field in PostMedia

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PostMediaId that = (PostMediaId) o;
        return Objects.equals(post, that.post) &&
                Objects.equals(media, that.media);
    }

    @Override
    public int hashCode() {
        return Objects.hash(post, media);
    }
}
