package com.stephensalano.fileflow_api.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor

public class CollectionMediaId implements Serializable {
    private static final long seialVersionUID = 1L;

    private UUID collection;
    private UUID media;

    @Override
    public boolean equals(Object o){
        if (this == o)return true;
        if (o == null || getClass() != o.getClass()) return false;
        CollectionMediaId that = (CollectionMediaId) o;
        return Objects.equals(collection, that.collection) && Objects.equals(media, that.media);
    }

    @Override
    public int hashCode(){
        return Objects.hash(collection, media);
    }
}
